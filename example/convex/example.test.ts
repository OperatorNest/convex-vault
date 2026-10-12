import { register } from "@operatornest/convex-vault/test";
import { generateMasterKey } from "@operatornest/convex-vault";
import { convexTest } from "convex-test";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { api, internal } from "./_generated/api.js";
import schema from "./schema.js";

const modules = import.meta.glob(["./**/*.ts", "!./**/*.test.ts"]);
beforeEach(() => {
  vi.useFakeTimers();
  vi.stubEnv("VAULT_KEYS", `1:${generateMasterKey()}`);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});
function setup() {
  const t = convexTest(schema, modules);
  register(t);
  return t;
}

it("authenticates every public operation and never accepts an owner argument", async () => {
  const t = setup();
  const ref = { kind: "providerKey" as const, name: "primary" };
  await expect(
    t.mutation(api.example.create, { ...ref, value: "test provider value" }),
  ).rejects.toThrow(/Not signed in/);
  await expect(t.mutation(api.example.reveal, ref)).rejects.toThrow(/Not signed in/);
  await expect(t.mutation(api.example.replace, { ...ref, value: "next" })).rejects.toThrow(
    /Not signed in/,
  );
  await expect(t.mutation(api.example.revoke, ref)).rejects.toThrow(/Not signed in/);
  await expect(
    t.mutation(api.example.verify, { kind: "sharedToken", value: "token" }),
  ).rejects.toThrow(/Not signed in/);
  await expect(t.query(api.example.get, ref)).rejects.toThrow(/Not signed in/);
  await expect(
    t.query(api.example.list, { paginationOpts: { numItems: 2, cursor: null } }),
  ).rejects.toThrow(/Not signed in/);
  await expect(
    t.query(api.example.listEvents, { paginationOpts: { numItems: 2, cursor: null } }),
  ).rejects.toThrow(/Not signed in/);
  const alice = t.withIdentity({ subject: "alice" });
  const bob = t.withIdentity({ subject: "bob" });
  await alice.mutation(api.example.create, { ...ref, value: "alice credential" });
  await bob.mutation(api.example.create, { ...ref, value: "bob credential" });
  expect(await alice.mutation(api.example.reveal, ref)).toEqual({ value: "alice credential" });
  expect(await bob.mutation(api.example.reveal, ref)).toEqual({ value: "bob credential" });
  await bob.mutation(api.example.revoke, ref);
  expect(await alice.mutation(api.example.reveal, ref)).toEqual({ value: "alice credential" });
  await alice.mutation(api.example.replace, { ...ref, value: "renewed credential", graceMs: 1000 });
  expect(await alice.query(api.example.get, ref)).toMatchObject({
    name: "primary",
    status: "active",
  });
  const list = await alice.query(api.example.list, {
    kind: "providerKey",
    paginationOpts: { numItems: 2, cursor: null },
  });
  expect(list.page).toHaveLength(1);
  const events = await alice.query(api.example.listEvents, {
    paginationOpts: { numItems: 100, cursor: null },
  });
  expect(events.page.some((event) => event.type === "replaced")).toBe(true);
});
it("verifies supplied tokens only within the authenticated owner before consuming uses", async () => {
  const t = setup();
  const alice = t.withIdentity({ subject: "alice" });
  const bob = t.withIdentity({ subject: "bob" });
  await alice.mutation(api.example.create, {
    kind: "sharedToken",
    name: "single",
    value: "test token",
    maxUses: 1,
  });
  expect(
    await bob.mutation(api.example.verify, { kind: "sharedToken", value: "test token" }),
  ).toMatchObject({ ok: false });
  expect(
    await alice.mutation(api.example.verify, { kind: "sharedToken", value: "test token" }),
  ).toMatchObject({ ok: true, usesLeft: 0 });
});
it("drives all six kinds through the internal server-side wrappers", async () => {
  const t = setup();
  for (const [kind, storage, generated] of [
    ["providerKey", "encrypted", false],
    ["signingSecret", "encrypted", true],
    ["sharedToken", "hashed", false],
    ["apiKey", "hashed", true],
    ["importedKey", "both", false],
    ["dashboardKey", "both", true],
  ] as const) {
    const created = await t.mutation(internal.admin.create, {
      kind,
      owner: "tenant",
      ...(generated ? {} : { value: `first-${kind}` }),
    });
    const ref = { entryId: created.entryId };
    const first = created.value ?? `first-${kind}`;
    if (storage !== "hashed")
      expect(await t.mutation(internal.admin.reveal, { ref })).toEqual({ value: first });
    if (
      kind === "sharedToken" ||
      kind === "apiKey" ||
      kind === "importedKey" ||
      kind === "dashboardKey"
    )
      expect(
        await t.mutation(internal.admin.verify, { kind, owner: "tenant", value: first }),
      ).toMatchObject({ ok: true });
    const next = await t.mutation(internal.admin.replace, {
      ref,
      graceMs: 1000,
      ...(generated ? {} : { value: `next-${kind}` }),
    });
    if (storage !== "hashed")
      expect(await t.mutation(internal.admin.reveal, { ref, includePrevious: true })).toMatchObject(
        { value: next.value ?? `next-${kind}`, previous: { value: first } },
      );
    expect(await t.query(internal.admin.get, { ref })).toMatchObject({ kind, owner: "tenant" });
    await t.mutation(internal.admin.revoke, { ref });
  }
  expect(
    (
      await t.query(internal.admin.list, {
        owner: "tenant",
        paginationOpts: { numItems: 100, cursor: null },
      })
    ).page,
  ).toHaveLength(6);
  expect(
    (
      await t.query(internal.admin.listEvents, {
        ref: { owner: "tenant" },
        paginationOpts: { numItems: 100, cursor: null },
      })
    ).page.some((event) => event.type === "revoked"),
  ).toBe(true);
  expect(await t.query(internal.admin.keyStatus, {})).toMatchObject({
    activeVersion: 1,
    missingVersions: [],
  });
  await t.mutation(internal.admin.rotateKeys, {});
  await t.finishAllScheduledFunctions(vi.runAllTimers);
});
it("rejects a missing value for supplied kinds and a supplied value for generated kinds", async () => {
  const t = setup();
  await expect(
    t.mutation(internal.admin.create, { kind: "providerKey", owner: "tenant" }),
  ).rejects.toThrow(/needs a value/);
  await expect(
    t.mutation(internal.admin.create, { kind: "apiKey", owner: "tenant", value: "unexpected" }),
  ).rejects.toThrow(/does not accept a value/);
});
