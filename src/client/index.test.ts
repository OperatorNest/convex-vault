import { convexTest } from "convex-test";
import { componentsGeneric, defineSchema } from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";
import { afterEach, beforeEach, expect, expectTypeOf, it, vi } from "vitest";
import { register } from "../test.js";
import { configureKeys, required, expectVaultError } from "../test-helpers.js";
import {
  Vault,
  type ReplaceOptions,
  type RevealOptions,
  type VaultReference,
  type VerifyOptions,
} from "./index.js";

const components = componentsGeneric() as ReturnType<typeof componentsGeneric> & {
  vault: ComponentApi;
};
const kinds = {
  provider: { storage: "encrypted" },
  issued: { storage: "hashed", generate: { prefix: "sk_", bytes: 16 }, ttlMs: 1000, maxUses: 1 },
  dual: { storage: "both", generate: { prefix: "wh_" }, hint: false, auditReveals: false },
  shared: { storage: "hashed", hint: true },
  imported: { storage: "both", lookup: "global" },
} as const;
const vault = new Vault(components.vault, { kinds });
const modules = import.meta.glob(["../component/**/*.ts", "!../component/**/*.test.ts"]);
function setup() {
  const t = convexTest(defineSchema({}), modules);
  register(t);
  return t;
}
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(1700000000000);
  configureKeys();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

it("uses typed kinds for reveal and verification and accepts standard Convex contexts", () => {
  expectTypeOf<Parameters<typeof vault.reveal>[1]>().toEqualTypeOf<
    VaultReference<"provider" | "dual" | "imported">
  >();
  expectTypeOf<Parameters<typeof vault.verify>[1]>().toEqualTypeOf<
    "issued" | "dual" | "shared" | "imported"
  >();
  expectTypeOf<Parameters<typeof vault.get>[1]>().toEqualTypeOf<
    VaultReference<keyof typeof kinds>
  >();
});
it("registers the component and runs every client method against real component functions", async () => {
  const t = setup();
  const provider = await t.run((ctx) =>
    vault.create(ctx, "provider", { owner: "tenant", name: "main", value: "provider secret" }),
  );
  const ref = { entryId: provider.entryId, kind: "provider" as const };
  expect(await t.run((ctx) => vault.reveal(ctx, ref))).toEqual({ value: "provider secret" });
  await t.run((ctx) => vault.replace(ctx, ref, { value: "replacement", graceMs: 100 }));
  expect(
    await t.run((ctx) =>
      vault.reveal(
        ctx,
        { owner: "tenant", kind: "provider", name: "main" },
        { includePrevious: true },
      ),
    ),
  ).toMatchObject({ value: "replacement", previous: { value: "provider secret" } });
  expect(await t.run((ctx) => vault.get(ctx, ref))).toMatchObject({
    storage: "encrypted",
    lookup: "owner",
    name: "main",
  });
  const issued = await t.run((ctx) => vault.create(ctx, "issued", { owner: "tenant" }));
  expect(issued.value).toMatch(/^sk_[A-Za-z0-9_-]{22}$/);
  expect(await t.run((ctx) => vault.verify(ctx, "issued", required(issued.value)))).toMatchObject({
    ok: true,
    usesLeft: 0,
  });
  expect(await t.run((ctx) => vault.get(ctx, { entryId: issued.entryId }))).toMatchObject({
    expiresAt: 1700000001000,
    maxUses: 1,
  });
  const dual = await t.run((ctx) => vault.create(ctx, "dual", { owner: "tenant" }));
  expect(dual.hint).toBeUndefined();
  await t.run((ctx) => vault.reveal(ctx, { entryId: dual.entryId }));
  expect(
    await t.run((ctx) =>
      vault.listEvents(ctx, { entryId: dual.entryId }, { numItems: 10, cursor: null }),
    ),
  ).toMatchObject({ page: [{ type: "created" }] });
  const shared = await t.run((ctx) =>
    vault.create(ctx, "shared", { owner: "tenant", value: "shared test credential" }),
  );
  expect(shared.hint).toBe("…tial");
  expect(
    await t.run((ctx) =>
      vault.verify(ctx, "shared", "shared test credential", { owner: "tenant" }),
    ),
  ).toMatchObject({ ok: true });
  await t.run((ctx) => vault.create(ctx, "imported", { owner: "tenant", value: "x".repeat(32) }));
  expect(await t.run((ctx) => vault.verify(ctx, "imported", "x".repeat(32)))).toMatchObject({
    ok: true,
  });
  expect(
    (
      await t.run((ctx) =>
        vault.list(ctx, { owner: "tenant", paginationOpts: { numItems: 10, cursor: null } }),
      )
    ).page,
  ).toHaveLength(5);
  expect(
    (
      await t.run((ctx) =>
        vault.list(ctx, {
          owner: "tenant",
          kind: "issued",
          paginationOpts: { numItems: 10, cursor: null },
        }),
      )
    ).page,
  ).toHaveLength(1);
  await t.run((ctx) => vault.rotateKeys(ctx));
  expect(await t.run((ctx) => vault.keyStatus(ctx))).toHaveProperty("activeVersion", 1);
  await t.run((ctx) => vault.revoke(ctx, ref, { actor: "operator" }));
  expect(await t.run((ctx) => vault.get(ctx, ref))).toHaveProperty("status", "revoked");
  expect(
    (
      await t.run((ctx) =>
        vault.listEvents(ctx, { owner: "tenant" }, { numItems: 100, cursor: null }),
      )
    ).page.some((event) => event.type === "revoked" && event.actor === "operator"),
  ).toBe(true);
});
it("allows create-time defaults to be overridden and does not combine a default TTL with explicit expiry", async () => {
  const t = setup();
  const created = await t.run((ctx) =>
    vault.create(ctx, "issued", { owner: "tenant", expiresAt: 1700000002000, maxUses: 3 }),
  );
  expect(await t.run((ctx) => vault.get(ctx, { entryId: created.entryId }))).toMatchObject({
    maxUses: 3,
    expiresAt: 1700000002000,
  });
  const another = await t.run((ctx) =>
    vault.create(ctx, "issued", { owner: "tenant", ttlMs: 3000 }),
  );
  expect(await t.run((ctx) => vault.get(ctx, { entryId: another.entryId }))).toHaveProperty(
    "expiresAt",
    1700000003000,
  );
});
it("ignores undeclared option fields, so options cannot redirect a call to another reference", async () => {
  const t = setup();
  const alice = { owner: "alice", kind: "provider", name: "main" } as const;
  const created = await t.run((ctx) =>
    vault.create(ctx, "provider", { ...alice, value: "alice secret" }),
  );
  const bob = await t.run((ctx) =>
    vault.create(ctx, "provider", { owner: "bob", name: "main", value: "bob secret" }),
  );
  const smuggled = { ref: { entryId: bob.entryId }, owner: "bob", kind: "dual", actor: "alice" };
  const revealOptions: RevealOptions = smuggled;
  const replaceOptions: ReplaceOptions = { ...smuggled, value: "alice replacement" };
  const revokeOptions: { actor?: string } = smuggled;
  expect(await t.run((ctx) => vault.reveal(ctx, alice, revealOptions))).toEqual({
    value: "alice secret",
  });
  await t.run((ctx) => vault.replace(ctx, alice, replaceOptions));
  await t.run((ctx) => vault.revoke(ctx, alice, revokeOptions));
  expect(await t.run((ctx) => vault.get(ctx, { entryId: created.entryId }))).toMatchObject({
    status: "revoked",
  });
  expect(await t.run((ctx) => vault.reveal(ctx, { entryId: bob.entryId }))).toEqual({
    value: "bob secret",
  });
  const issued = await t.run((ctx) => vault.create(ctx, "issued", { owner: "alice" }));
  const smuggledVerify = { owner: "alice", kind: "shared", value: "wrong" };
  const verifyOptions: VerifyOptions = smuggledVerify;
  expect(
    await t.run((ctx) => vault.verify(ctx, "issued", required(issued.value), verifyOptions)),
  ).toMatchObject({ ok: true });
});
it("fails closed for undeclared kinds and storage-incompatible references at runtime", async () => {
  const t = setup();
  const dynamic = new Vault<Record<string, { storage: "encrypted" | "hashed" }>>(components.vault, {
    kinds: { secret: { storage: "encrypted" }, hash: { storage: "hashed" } },
  });
  await expectVaultError(
    t.run((ctx) => dynamic.create(ctx, "missing", { owner: "tenant", value: "x" })),
    "VAULT_INVALID_ARGUMENT",
  );
  await expectVaultError(
    t.run((ctx) => dynamic.get(ctx, { entryId: "missing", kind: "missing" })),
    "VAULT_INVALID_ARGUMENT",
  );
  await expectVaultError(
    t.run((ctx) =>
      dynamic.list(ctx, {
        owner: "tenant",
        kind: "missing",
        paginationOpts: { numItems: 10, cursor: null },
      }),
    ),
    "VAULT_INVALID_ARGUMENT",
  );
  // Simulate a JavaScript caller mutating options after TypeScript construction.
  const changed = new Vault(components.vault, {
    kinds: { hash: { storage: "both" }, secret: { storage: "both", lookup: "global" } },
  });
  Object.assign(changed.options.kinds.hash, { storage: "hashed" });
  Object.assign(changed.options.kinds.secret, { storage: "encrypted" });
  await expectVaultError(
    t.run((ctx) => changed.reveal(ctx, { entryId: "unused", kind: "hash" })),
    "VAULT_NOT_REVEALABLE",
  );
  await expectVaultError(
    t.run((ctx) => changed.verify(ctx, "secret", "unused")),
    "VAULT_NOT_VERIFIABLE",
  );
});
