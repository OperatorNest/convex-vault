import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "./_generated/api.js";
import { configureKeys, expectVaultError, setupTest, required } from "../test-helpers.js";
import { generateMasterKey } from "../shared/keyring.js";
import type { PaginationResult, FunctionArgs } from "convex/server";
import type { Entry, Storage } from "../shared/validators.js";

const START = 1700000000000;
const input = (
  overrides: Partial<FunctionArgs<typeof api.vault.create>> = {},
): FunctionArgs<typeof api.vault.create> => ({
  owner: "tenant",
  kind: "shared",
  storage: "both",
  origin: "supplied",
  lookup: "owner",
  value: "a sufficiently long test credential",
  ...overrides,
});
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(START);
  configureKeys();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

describe("public credential lifecycle", () => {
  const combinations = (["encrypted", "hashed", "both"] as const).flatMap((storage) =>
    (["supplied", "generated"] as const).map((origin) => ({ storage, origin })),
  );
  it.each(combinations)(
    "supports $storage / $origin through replace, grace and revoke",
    async ({ storage, origin }) => {
      const t = setupTest();
      const generated = origin === "generated";
      const created = await t.mutation(
        api.vault.create,
        input({
          storage,
          origin,
          lookup: generated ? "global" : "owner",
          value: generated ? undefined : "first supplied test credential",
          prefix: generated ? "sk_" : undefined,
          scopes: ["read"],
          metadata: { tier: 1, enabled: true, note: null },
        }),
      );
      const first = generated ? required(created.value) : "first supplied test credential";
      expect(created.value !== undefined).toBe(generated);
      expect(created.hint !== undefined).toBe(generated);
      const ref = { entryId: created.entryId };
      if (storage !== "hashed")
        expect(await t.mutation(api.vault.reveal, { ref })).toEqual({ value: first });
      else await expectVaultError(t.mutation(api.vault.reveal, { ref }), "VAULT_NOT_REVEALABLE");
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.vault.verify, {
            kind: "shared",
            value: first,
            owner: "tenant",
            requiredScopes: ["read"],
          }),
        ).toMatchObject({
          ok: true,
          entryId: created.entryId,
          owner: "tenant",
          scopes: ["read"],
          metadata: { tier: 1 },
        });
      else
        await expectVaultError(
          t.mutation(api.vault.verify, { kind: "shared", value: first }),
          "VAULT_NOT_VERIFIABLE",
        );
      const replaced = await t.mutation(api.vault.replace, {
        ref,
        value: generated ? undefined : "second supplied test credential",
        graceMs: 1000,
      });
      const second = generated ? required(replaced.value) : "second supplied test credential";
      expect(second).not.toBe(first);
      if (storage !== "hashed")
        expect(await t.mutation(api.vault.reveal, { ref, includePrevious: true })).toEqual({
          value: second,
          previous: { value: first, validUntil: START + 1000 },
        });
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.vault.verify, { kind: "shared", value: first, owner: "tenant" }),
        ).toMatchObject({ ok: true });
      vi.setSystemTime(START + 1000);
      if (storage !== "hashed")
        expect(await t.mutation(api.vault.reveal, { ref, includePrevious: true })).toEqual({
          value: second,
        });
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.vault.verify, { kind: "shared", value: first, owner: "tenant" }),
        ).toEqual({ ok: false, reason: "expired" });
      await t.mutation(api.vault.revoke, { ref, actor: "operator" });
      await t.mutation(api.vault.revoke, { ref });
      expect(await t.query(api.vault.get, { ref })).toMatchObject({ status: "revoked" });
      expect(await t.run((ctx) => ctx.db.query("values").take(10))).toEqual([]);
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.vault.verify, { kind: "shared", value: second, owner: "tenant" }),
        ).toEqual({ ok: false, reason: "not_found" });
      await expectVaultError(
        t.mutation(api.vault.replace, { ref, value: "next" }),
        "VAULT_INACTIVE",
      );
      await expectVaultError(t.mutation(api.vault.reveal, { ref }), "VAULT_INACTIVE");
      const events = await t.query(api.vault.listEvents, {
        ref,
        paginationOpts: { numItems: 100, cursor: null },
      });
      expect(events.page.filter((event) => event.type === "revoked")).toHaveLength(1);
    },
  );
  it("requires owner for owner lookup and keeps values isolated by owner and kind", async () => {
    const t = setupTest();
    await t.mutation(api.vault.create, input());
    const verify = { kind: "shared", value: input().value ?? "" };
    await expectVaultError(t.mutation(api.vault.verify, verify), "VAULT_INVALID_ARGUMENT");
    expect(await t.mutation(api.vault.verify, { ...verify, owner: "other" })).toEqual({
      ok: false,
      reason: "not_found",
    });
    expect(await t.mutation(api.vault.verify, { ...verify, owner: "tenant" })).toMatchObject({
      ok: true,
      owner: "tenant",
    });
    await t.mutation(api.vault.create, input({ owner: "other" }));
    await t.mutation(api.vault.create, input({ kind: "another" }));
    expect(await t.mutation(api.vault.verify, { ...verify, owner: "other" })).toMatchObject({
      ok: true,
      owner: "other",
    });
    expect(
      await t.mutation(api.vault.verify, { ...verify, kind: "unknown", owner: "tenant" }),
    ).toEqual({ ok: false, reason: "not_found" });
    expect(
      await t.mutation(api.vault.verify, { ...verify, value: "wrong", owner: "tenant" }),
    ).toEqual({ ok: false, reason: "not_found" });
  });
  it("requires long supplied global values and restricts global verification to a given owner", async () => {
    const t = setupTest();
    await expectVaultError(
      t.mutation(api.vault.create, input({ lookup: "global", value: "short", maxUses: 2 })),
      "VAULT_INVALID_ARGUMENT",
    );
    await t.mutation(
      api.vault.create,
      input({ lookup: "global", value: "x".repeat(32), maxUses: 2 }),
    );
    const verify = (owner?: string) =>
      t.mutation(api.vault.verify, { kind: "shared", value: "x".repeat(32), owner });
    expect(await verify("unrelated")).toEqual({ ok: false, reason: "not_found" });
    expect(await verify("tenant")).toMatchObject({ ok: true, owner: "tenant", usesLeft: 1 });
    expect(await verify()).toMatchObject({ ok: true, owner: "tenant", usesLeft: 0 });
  });
  it("never lets grace extend an old value past the expiry it had before replace", async () => {
    const t = setupTest();
    const old = "old supplied test credential";
    const verify = (value: string) =>
      t.mutation(api.vault.verify, { kind: "shared", value, owner: "tenant" });
    const a = await t.mutation(api.vault.create, input({ value: old, ttlMs: 1000 }));
    vi.setSystemTime(START + 1000);
    await t.mutation(api.vault.replace, {
      ref: { entryId: a.entryId },
      value: "renewed supplied credential",
      ttlMs: 10_000,
      graceMs: 5000,
    });
    expect(await verify(old)).toEqual({ ok: false, reason: "not_found" });
    expect(
      await t.mutation(api.vault.reveal, { ref: { entryId: a.entryId }, includePrevious: true }),
    ).toEqual({ value: "renewed supplied credential" });
    const b = await t.mutation(
      api.vault.create,
      input({ kind: "capped", value: old, ttlMs: 3000 }),
    );
    await t.mutation(api.vault.replace, {
      ref: { entryId: b.entryId },
      value: "capped replacement credential",
      ttlMs: 10_000,
      graceMs: 5000,
    });
    expect(
      await t.mutation(api.vault.reveal, { ref: { entryId: b.entryId }, includePrevious: true }),
    ).toEqual({
      value: "capped replacement credential",
      previous: { value: old, validUntil: START + 4000 },
    });
    vi.setSystemTime(START + 4000);
    expect(
      await t.mutation(api.vault.verify, { kind: "capped", value: old, owner: "tenant" }),
    ).toEqual({ ok: false, reason: "expired" });
  });
  it("resolves an entry ID reference only for the kind it names", async () => {
    const t = setupTest();
    const a = await t.mutation(api.vault.create, input({ storage: "encrypted", kind: "secret" }));
    await expectVaultError(
      t.mutation(api.vault.reveal, { ref: { entryId: a.entryId, kind: "other" } }),
      "VAULT_NOT_FOUND",
    );
    await expectVaultError(
      t.mutation(api.vault.revoke, { ref: { entryId: a.entryId, kind: "other" } }),
      "VAULT_NOT_FOUND",
    );
    expect(
      await t.mutation(api.vault.reveal, { ref: { entryId: a.entryId, kind: "secret" } }),
    ).toEqual({ value: input().value });
  });
  it("rejects duplicate values across key versions, across owners under global lookup, and against expired previous values", async () => {
    const t = setupTest();
    const old = configureKeys();
    const a = await t.mutation(api.vault.create, input());
    await expectVaultError(t.mutation(api.vault.create, input()), "VAULT_DUPLICATE_VALUE");
    vi.stubEnv("VAULT_KEYS", `2:${generateMasterKey()},1:${old}`);
    await expectVaultError(t.mutation(api.vault.create, input()), "VAULT_DUPLICATE_VALUE");
    await t.mutation(api.vault.replace, { ref: { entryId: a.entryId }, value: "next", graceMs: 1 });
    vi.setSystemTime(START + 2);
    await expectVaultError(t.mutation(api.vault.create, input()), "VAULT_DUPLICATE_VALUE");
    await expectVaultError(
      t.mutation(api.vault.replace, { ref: { entryId: a.entryId }, value: "next" }),
      "VAULT_DUPLICATE_VALUE",
    );
    await t.mutation(
      api.vault.create,
      input({ kind: "global", lookup: "global", value: "y".repeat(32) }),
    );
    await expectVaultError(
      t.mutation(
        api.vault.create,
        input({ kind: "global", owner: "other", lookup: "global", value: "y".repeat(32) }),
      ),
      "VAULT_DUPLICATE_VALUE",
    );
  });
  it("records immutable kind policy and reserves unique owner/kind/name identities", async () => {
    const t = setupTest();
    const created = await t.mutation(api.vault.create, input({ name: "primary" }));
    for (const change of [
      { storage: "hashed" as Storage },
      { origin: "generated" as const, value: undefined, lookup: "global" as const },
      { lookup: "global" as const },
    ]) {
      await expectVaultError(t.mutation(api.vault.create, input(change)), "VAULT_KIND_CONFLICT");
    }
    await expectVaultError(
      t.mutation(api.vault.create, input({ name: "primary", value: "other" })),
      "VAULT_DUPLICATE_NAME",
    );
    expect(
      await t.query(api.vault.get, { ref: { owner: "tenant", kind: "shared", name: "primary" } }),
    ).toMatchObject({ entryId: created.entryId });
    await t.mutation(api.vault.create, input({ owner: "other", name: "primary" }));
    await expectVaultError(
      t.query(api.vault.get, { ref: { entryId: "missing" } }),
      "VAULT_NOT_FOUND",
    );
    await expectVaultError(
      t.query(api.vault.get, { ref: { owner: "tenant", kind: "shared", name: "missing" } }),
      "VAULT_NOT_FOUND",
    );
  });
  it("releases revoked names and no longer resolves them, keeping the revoke event", async () => {
    const t = setupTest();
    const created = await t.mutation(api.vault.create, input({ name: "primary" }));
    const ref = { entryId: created.entryId };
    await t.mutation(api.vault.revoke, { ref });
    await t.mutation(api.vault.revoke, { ref });
    await expectVaultError(
      t.query(api.vault.get, { ref: { owner: "tenant", kind: "shared", name: "primary" } }),
      "VAULT_NOT_FOUND",
    );
    expect(await t.query(api.vault.get, { ref })).not.toHaveProperty("name");
    const next = await t.mutation(api.vault.create, input({ name: "primary", value: "next" }));
    expect(next.entryId).not.toBe(created.entryId);
    const events = await t.query(api.vault.listEvents, {
      ref,
      paginationOpts: { numItems: 100, cursor: null },
    });
    expect(events.page.filter((event) => event.type === "revoked")).toHaveLength(1);
  });
  it.each(["reveal", "verify"] as const)(
    "releases an exhausted name through %s",
    async (operation) => {
      const t = setupTest();
      const created = await t.mutation(api.vault.create, input({ name: "primary", maxUses: 1 }));
      const ref = { entryId: created.entryId };
      if (operation === "reveal") await t.mutation(api.vault.reveal, { ref });
      else
        await t.mutation(api.vault.verify, {
          kind: "shared",
          owner: "tenant",
          value: input().value ?? "",
        });
      expect(await t.query(api.vault.get, { ref })).toMatchObject({ status: "exhausted" });
      expect(await t.query(api.vault.get, { ref })).not.toHaveProperty("name");
      await expectVaultError(
        t.query(api.vault.get, {
          ref: { owner: "tenant", kind: "shared", name: "primary" },
        }),
        "VAULT_NOT_FOUND",
      );
      await t.mutation(api.vault.create, input({ name: "primary", value: "next" }));
      const events = await t.query(api.vault.listEvents, {
        ref,
        paginationOpts: { numItems: 100, cursor: null },
      });
      expect(events.page.filter((event) => event.type === "exhausted")).toHaveLength(1);
    },
  );
  it("rejects expiry exactly at the boundary and renews an expired entry only through replace with new expiry", async () => {
    const t = setupTest();
    const a = await t.mutation(api.vault.create, input({ ttlMs: 1000 }));
    const ref = { entryId: a.entryId };
    vi.setSystemTime(START + 999);
    expect(
      await t.mutation(api.vault.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toMatchObject({ ok: true });
    expect(await t.mutation(api.vault.reveal, { ref })).toHaveProperty("value");
    vi.setSystemTime(START + 1000);
    expect(
      await t.mutation(api.vault.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toEqual({ ok: false, reason: "expired" });
    await expectVaultError(t.mutation(api.vault.reveal, { ref }), "VAULT_INACTIVE");
    await expectVaultError(
      t.mutation(api.vault.replace, { ref, value: "unrenewed" }),
      "VAULT_INACTIVE",
    );
    await t.mutation(api.vault.replace, { ref, value: "renewed", ttlMs: 500 });
    expect(await t.mutation(api.vault.reveal, { ref })).toEqual({ value: "renewed" });
    expect(await t.query(api.vault.get, { ref })).toHaveProperty("expiresAt", START + 1500);
    await t.mutation(api.vault.replace, { ref, value: "third" });
    expect(await t.query(api.vault.get, { ref })).toHaveProperty("expiresAt", START + 1500);
    await t.mutation(api.vault.replace, { ref, value: "fourth", expiresAt: START + 2000 });
    expect(await t.query(api.vault.get, { ref })).toHaveProperty("expiresAt", START + 2000);
  });
  it("consumes one maxUses limit from verify and reveal and consumes no use on a missing scope", async () => {
    const t = setupTest();
    const a = await t.mutation(api.vault.create, input({ maxUses: 2, scopes: ["read"] }));
    const ref = { entryId: a.entryId };
    expect(
      await t.mutation(api.vault.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
        requiredScopes: ["write"],
      }),
    ).toEqual({ ok: false, reason: "missing_scope" });
    expect(
      await t.mutation(api.vault.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toMatchObject({ ok: true, usesLeft: 1 });
    await t.mutation(api.vault.reveal, { ref });
    expect(await t.query(api.vault.get, { ref })).toMatchObject({
      useCount: 2,
      status: "exhausted",
    });
    expect(
      await t.mutation(api.vault.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toEqual({ ok: false, reason: "exhausted" });
    await expectVaultError(t.mutation(api.vault.reveal, { ref }), "VAULT_INACTIVE");
    await expectVaultError(t.mutation(api.vault.replace, { ref, value: "new" }), "VAULT_INACTIVE");
    const events = await t.query(api.vault.listEvents, {
      ref,
      paginationOpts: { numItems: 100, cursor: null },
    });
    expect(events.page.filter((event) => event.type === "exhausted")).toHaveLength(1);
  });
  it.each(["reveal", "verify"] as const)(
    "serializes two concurrent %s calls for a single-use entry",
    async (operation) => {
      const t = setupTest();
      const a = await t.mutation(api.vault.create, input({ maxUses: 1 }));
      const call = () =>
        operation === "reveal"
          ? t.mutation(api.vault.reveal, { ref: { entryId: a.entryId } })
          : t.mutation(api.vault.verify, {
              kind: "shared",
              value: input().value ?? "",
              owner: "tenant",
            });
      const results = await Promise.allSettled([call(), call()]);
      const succeeded = results.filter(
        (result) => result.status === "fulfilled" && (!("ok" in result.value) || result.value.ok),
      );
      expect(succeeded).toHaveLength(1);
    },
  );
  it("without maxUses, writes nothing on reveal and writes lastUsedAt at most once per 60 seconds on verify", async () => {
    const t = setupTest();
    const a = await t.mutation(api.vault.create, input({ auditReveals: false }));
    const ref = { entryId: a.entryId };
    const before = await t.query(api.vault.get, { ref });
    await t.mutation(api.vault.reveal, { ref });
    expect(await t.query(api.vault.get, { ref })).toEqual(before);
    expect(
      (
        await t.query(api.vault.listEvents, {
          ref,
          paginationOpts: { numItems: 100, cursor: null },
        })
      ).page,
    ).toHaveLength(1);
    const verify = { kind: "shared", owner: "tenant", value: input().value ?? "" };
    await t.mutation(api.vault.verify, verify);
    vi.setSystemTime(START + 59999);
    await t.mutation(api.vault.verify, verify);
    expect(await t.query(api.vault.get, { ref })).toMatchObject({
      lastUsedAt: START,
      updatedAt: START,
      useCount: 0,
    });
    vi.setSystemTime(START + 60000);
    await t.mutation(api.vault.verify, verify);
    expect(await t.query(api.vault.get, { ref })).toMatchObject({
      lastUsedAt: START + 60000,
      updatedAt: START,
      useCount: 0,
    });
  });
  it("keeps creation-time generation settings and replaces the single previous value", async () => {
    const t = setupTest();
    const a = await t.mutation(
      api.vault.create,
      input({
        origin: "generated",
        lookup: "global",
        value: undefined,
        prefix: "old_",
        bytes: 16,
        hint: false,
      }),
    );
    await t.mutation(
      api.vault.create,
      input({ origin: "generated", lookup: "global", value: undefined, prefix: "new_", bytes: 64 }),
    );
    const ref = { entryId: a.entryId };
    const b = await t.mutation(api.vault.replace, { ref, graceMs: 1000 });
    expect(b.value).toMatch(/^old_[A-Za-z0-9_-]{22}$/);
    expect(b.hint).toBeUndefined();
    const c = await t.mutation(api.vault.replace, { ref, graceMs: 2000 });
    expect(
      await t.mutation(api.vault.verify, { kind: "shared", value: required(a.value) }),
    ).toEqual({ ok: false, reason: "not_found" });
    expect(await t.mutation(api.vault.reveal, { ref, includePrevious: true })).toEqual({
      value: c.value,
      previous: { value: b.value, validUntil: START + 2000 },
    });
  });
  it("paginates owner metadata and audit events without exposing values, ciphertext or hashes", async () => {
    const t = setupTest();
    const outputs: unknown[] = [];
    for (const kind of ["a", "b"])
      for (let i = 0; i < 3; i++)
        outputs.push(
          await t.mutation(
            api.vault.create,
            input({ kind, name: `key${i}`, value: `${kind}${i}` }),
          ),
        );
    await t.mutation(api.vault.create, input({ owner: "other" }));
    let cursor: string | null = null;
    const ids = [];
    do {
      const page: PaginationResult<Entry> = await t.query(api.vault.list, {
        owner: "tenant",
        paginationOpts: { numItems: 2, cursor },
      });
      outputs.push(page);
      expect(page.page.every((row) => row.owner === "tenant")).toBe(true);
      ids.push(...page.page.map((row) => row.entryId));
      cursor = page.isDone ? null : page.continueCursor;
    } while (cursor !== null);
    expect(new Set(ids).size).toBe(6);
    const first = required(ids[0]);
    outputs.push(await t.query(api.vault.get, { ref: { entryId: first } }));
    const filtered = await t.query(api.vault.list, {
      owner: "tenant",
      kind: "a",
      paginationOpts: { numItems: 100, cursor: null },
    });
    outputs.push(filtered);
    expect(filtered.page).toHaveLength(3);
    outputs.push(
      await t.query(api.vault.listEvents, {
        ref: { owner: "tenant" },
        paginationOpts: { numItems: 2, cursor: null },
      }),
    );
    outputs.push(await t.query(api.maintenance.keyStatus, {}));
    outputs.push(await t.mutation(api.maintenance.rotateKeys, {}));
    outputs.push(await t.mutation(api.vault.reveal, { ref: { entryId: first } }));
    outputs.push(await t.mutation(api.vault.replace, { ref: { entryId: first }, value: "new" }));
    outputs.push(await t.mutation(api.vault.verify, { kind: "b", owner: "tenant", value: "new" }));
    outputs.push(await t.mutation(api.vault.revoke, { ref: { entryId: first } }));
    expect(JSON.stringify(outputs)).not.toMatch(/ciphertext|wrappedKey|lookupHash|keyIv/);
  });
  it("reads at most numItems + 1 rows when a page request passes endCursor", async () => {
    const t = setupTest();
    for (let i = 0; i < 5; i++)
      await t.mutation(api.vault.create, input({ name: `key${i}`, value: `value${i}` }));
    const paginationOpts = { numItems: 1, cursor: null, endCursor: "[]" };
    const entries = await t.query(api.vault.list, { owner: "tenant", paginationOpts });
    expect(entries).toMatchObject({ isDone: false, pageStatus: "SplitRequired" });
    expect(entries.page).toHaveLength(2);
    const events = await t.query(api.vault.listEvents, {
      ref: { owner: "tenant" },
      paginationOpts,
    });
    expect(events.page).toHaveLength(2);
  });
  it.each(["not-json", "5", '{"key":1}', '[{"$integer":"x"}]', ""])(
    "rejects the malformed page cursor %j with a structured error",
    async (cursor) => {
      const t = setupTest();
      for (const paginationOpts of [
        { numItems: 10, cursor },
        { numItems: 10, cursor: null, endCursor: cursor },
      ]) {
        await expectVaultError(
          t.query(api.vault.list, { owner: "tenant", paginationOpts }),
          "VAULT_INVALID_ARGUMENT",
        );
        await expectVaultError(
          t.query(api.vault.listEvents, { ref: { owner: "tenant" }, paginationOpts }),
          "VAULT_INVALID_ARGUMENT",
        );
      }
    },
  );
  it.each([undefined, "bad", "1:AA"])(
    "fails every public operation closed for configuration %s",
    async (config) => {
      const t = setupTest();
      vi.stubEnv("VAULT_KEYS", config);
      const ref = { entryId: "missing" };
      const page = { numItems: 10, cursor: null };
      const calls = [
        t.mutation(api.vault.create, input()),
        t.mutation(api.vault.reveal, { ref }),
        t.mutation(api.vault.verify, { kind: "shared", value: "test" }),
        t.mutation(api.vault.replace, { ref }),
        t.mutation(api.vault.revoke, { ref }),
        t.query(api.vault.get, { ref }),
        t.query(api.vault.list, { owner: "tenant", paginationOpts: page }),
        t.query(api.vault.listEvents, { ref, paginationOpts: page }),
        t.query(api.maintenance.keyStatus, {}),
        t.mutation(api.maintenance.rotateKeys, {}),
      ];
      await Promise.all(calls.map((call) => expectVaultError(call, "VAULT_NOT_CONFIGURED")));
    },
  );
});

describe("argument bounds", () => {
  it.each([
    { owner: "" },
    { owner: "x".repeat(257) },
    { kind: "x".repeat(129) },
    { name: "x".repeat(129) },
    { label: "x".repeat(257) },
    { actor: "x".repeat(257) },
    { value: "" },
    { value: "😀".repeat(4097) },
    { scopes: Array.from({ length: 33 }, () => "read") },
    { scopes: ["x".repeat(65)] },
    { metadata: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`key${i}`, true])) },
    { metadata: { key: "x".repeat(4096) } },
    { metadata: { key: Number.NaN } },
    { ttlMs: 0 },
    { ttlMs: -1 },
    { ttlMs: 1.5 },
    { ttlMs: Number.POSITIVE_INFINITY },
    { ttlMs: 1, expiresAt: START + 100 },
    { expiresAt: START },
    { maxUses: 0 },
    { maxUses: 1.5 },
    { origin: "generated" as const, lookup: "owner" as const, value: undefined },
    { origin: "generated" as const, lookup: "global" as const },
    { origin: "generated" as const, lookup: "global" as const, value: undefined, prefix: "bad!" },
    { origin: "generated" as const, lookup: "global" as const, value: undefined, bytes: 15 },
    { origin: "generated" as const, lookup: "global" as const, value: undefined, bytes: 65 },
    { origin: "generated" as const, lookup: "global" as const, value: undefined, bytes: 16.5 },
    { prefix: "x" },
    { bytes: 32 },
    { value: undefined },
  ])("rejects invalid create options %#", async (overrides) => {
    const t = setupTest();
    await expectVaultError(
      t.mutation(api.vault.create, input(overrides)),
      "VAULT_INVALID_ARGUMENT",
    );
    expect(await t.run((ctx) => ctx.db.query("entries").take(1))).toEqual([]);
  });
  it("accepts UTF-8, metadata, and generation bounds at their limits", async () => {
    const t = setupTest();
    await t.mutation(
      api.vault.create,
      input({
        value: "😀".repeat(4096),
        scopes: Array.from({ length: 32 }, (_, i) => `scope${i}`),
        metadata: Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`key${i}`, true])),
      }),
    );
    await t.mutation(
      api.vault.create,
      input({
        kind: "generated",
        origin: "generated",
        lookup: "global",
        value: undefined,
        prefix: "x".repeat(32),
        bytes: 64,
      }),
    );
  });
  it("validates replacement and pagination options", async () => {
    const t = setupTest();
    const a = await t.mutation(api.vault.create, input());
    const ref = { entryId: a.entryId };
    for (const graceMs of [-1, 0.5, Number.NaN])
      await expectVaultError(
        t.mutation(api.vault.replace, { ref, value: "new", graceMs }),
        "VAULT_INVALID_ARGUMENT",
      );
    await expectVaultError(t.mutation(api.vault.replace, { ref }), "VAULT_INVALID_ARGUMENT");
    await expectVaultError(
      t.mutation(api.vault.replace, { ref, value: "" }),
      "VAULT_INVALID_ARGUMENT",
    );
    for (const numItems of [0, 101, 1.5]) {
      await expectVaultError(
        t.query(api.vault.list, { owner: "tenant", paginationOpts: { numItems, cursor: null } }),
        "VAULT_INVALID_ARGUMENT",
      );
      await expectVaultError(
        t.query(api.vault.listEvents, { ref, paginationOpts: { numItems, cursor: null } }),
        "VAULT_INVALID_ARGUMENT",
      );
    }
  });
});
