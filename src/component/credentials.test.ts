import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, internal } from "./_generated/api.js";
import { configureKeys, drain, expectVaultError, setupTest, required } from "../test-helpers.js";
import { generateMasterKey } from "../shared/keyring.js";
import { isVaultError } from "../shared/errors.js";
import type { PaginationResult, FunctionArgs } from "convex/server";
import type { Credential, Storage } from "../shared/validators.js";

const START = 1700000000000;
const input = (
  overrides: Partial<FunctionArgs<typeof api.credentials.create>> = {},
): FunctionArgs<typeof api.credentials.create> => ({
  owner: "tenant",
  kind: "shared",
  storage: "both",
  origin: "supplied",
  lookup: "owner",
  bytes: overrides.origin === "generated" ? 32 : undefined,
  hint: false,
  auditReveals: true,
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

describe("credential lifecycle", () => {
  const combinations = (["encrypted", "hashed", "both"] as const).flatMap((storage) =>
    (["supplied", "generated"] as const).map((origin) => ({ storage, origin })),
  );
  it.each(combinations)(
    "supports $storage / $origin through replace, grace and revoke",
    async ({ storage, origin }) => {
      const t = setupTest();
      const generated = origin === "generated";
      const created = await t.mutation(
        api.credentials.create,
        input({
          storage,
          origin,
          hint: generated,
          lookup: generated ? "global" : "owner",
          value: generated ? undefined : "first supplied test credential",
          prefix: generated ? "sk_" : undefined,
          scopes: ["read"],
          metadata: { tier: 1, enabled: true, note: null },
        }),
      );
      const first = generated
        ? required(created.value, "generated value")
        : "first supplied test credential";
      expect(created.value !== undefined).toBe(generated);
      expect(created.hint !== undefined).toBe(generated);
      const ref = { credentialId: created.credentialId };
      if (storage !== "hashed")
        expect(await t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref })).toEqual({
          value: first,
        });
      else
        await expectVaultError(
          t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref }),
          "VAULT_NOT_REVEALABLE",
        );
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.credentials.verify, {
            kind: "shared",
            value: first,
            owner: "tenant",
            requiredScopes: ["read"],
          }),
        ).toMatchObject({
          ok: true,
          credentialId: created.credentialId,
          owner: "tenant",
          scopes: ["read"],
          metadata: { tier: 1 },
        });
      else
        await expectVaultError(
          t.mutation(api.credentials.verify, { kind: "shared", value: first }),
          "VAULT_NOT_VERIFIABLE",
        );
      const replaced = await t.mutation(api.credentials.replace, {
        ref,
        value: generated ? undefined : "second supplied test credential",
        graceMs: 1000,
      });
      const second = generated
        ? required(replaced.value, "replacement value")
        : "second supplied test credential";
      expect(second).not.toBe(first);
      if (storage !== "hashed")
        expect(
          await t.mutation(api.credentials.reveal, {
            auditRevealsKinds: [],
            ref,
            includePrevious: true,
          }),
        ).toEqual({
          value: second,
          previous: { value: first, validUntilAt: START + 1000 },
        });
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.credentials.verify, {
            kind: "shared",
            value: first,
            owner: "tenant",
          }),
        ).toMatchObject({ ok: true });
      vi.setSystemTime(START + 1000);
      if (storage !== "hashed")
        expect(
          await t.mutation(api.credentials.reveal, {
            auditRevealsKinds: [],
            ref,
            includePrevious: true,
          }),
        ).toEqual({
          value: second,
        });
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.credentials.verify, {
            kind: "shared",
            value: first,
            owner: "tenant",
          }),
        ).toEqual({ ok: false, reason: "expired" });
      await t.mutation(api.credentials.revoke, { ref, actor: "operator" });
      await t.mutation(api.credentials.revoke, { ref });
      expect(await t.query(api.credentials.get, { ref })).toMatchObject({ status: "revoked" });
      expect(await t.run((ctx) => ctx.db.query("values").take(10))).toEqual([]);
      if (storage !== "encrypted")
        expect(
          await t.mutation(api.credentials.verify, {
            kind: "shared",
            value: second,
            owner: "tenant",
          }),
        ).toEqual({ ok: false, reason: "not_found" });
      await expectVaultError(
        t.mutation(api.credentials.replace, { ref, value: "next" }),
        "VAULT_INACTIVE",
      );
      await expectVaultError(
        t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref }),
        "VAULT_INACTIVE",
      );
      const events = await t.query(api.events.list, {
        ref,
        paginationOpts: { numItems: 100, cursor: null },
      });
      expect(events.page.filter((event) => event.type === "revoked")).toHaveLength(1);
    },
  );
  it("requires owner for owner lookup and keeps values isolated by owner and kind", async () => {
    const t = setupTest();
    await t.mutation(api.credentials.create, input());
    const verify = { kind: "shared", value: input().value ?? "" };
    await expectVaultError(t.mutation(api.credentials.verify, verify), "VAULT_INVALID_ARGUMENT");
    expect(await t.mutation(api.credentials.verify, { ...verify, owner: "other" })).toEqual({
      ok: false,
      reason: "not_found",
    });
    expect(await t.mutation(api.credentials.verify, { ...verify, owner: "tenant" })).toMatchObject({
      ok: true,
      owner: "tenant",
    });
    await t.mutation(api.credentials.create, input({ owner: "other" }));
    await t.mutation(api.credentials.create, input({ kind: "another" }));
    expect(await t.mutation(api.credentials.verify, { ...verify, owner: "other" })).toMatchObject({
      ok: true,
      owner: "other",
    });
    expect(
      await t.mutation(api.credentials.verify, { ...verify, kind: "unknown", owner: "tenant" }),
    ).toEqual({ ok: false, reason: "not_found" });
    expect(
      await t.mutation(api.credentials.verify, { ...verify, value: "wrong", owner: "tenant" }),
    ).toEqual({ ok: false, reason: "not_found" });
  });
  it("requires long supplied global values and restricts global verification to a given owner", async () => {
    const t = setupTest();
    await expectVaultError(
      t.mutation(api.credentials.create, input({ lookup: "global", value: "short", maxUses: 2 })),
      "VAULT_INVALID_ARGUMENT",
    );
    await t.mutation(
      api.credentials.create,
      input({ lookup: "global", value: "x".repeat(32), maxUses: 2 }),
    );
    const verify = (owner?: string) =>
      t.mutation(api.credentials.verify, { kind: "shared", value: "x".repeat(32), owner });
    expect(await verify("unrelated")).toEqual({ ok: false, reason: "not_found" });
    expect(await verify("tenant")).toMatchObject({ ok: true, owner: "tenant", usesLeft: 1 });
    expect(await verify()).toMatchObject({ ok: true, owner: "tenant", usesLeft: 0 });
  });
  it("never lets grace extend an old value past the expiry it had before replace", async () => {
    const t = setupTest();
    const old = "old supplied test credential";
    const verify = (value: string) =>
      t.mutation(api.credentials.verify, { kind: "shared", value, owner: "tenant" });
    const a = await t.mutation(api.credentials.create, input({ value: old, ttlMs: 1000 }));
    vi.setSystemTime(START + 1000);
    await t.mutation(api.credentials.replace, {
      ref: { credentialId: a.credentialId },
      value: "renewed supplied credential",
      ttlMs: 10_000,
      graceMs: 5000,
    });
    expect(await verify(old)).toEqual({ ok: false, reason: "not_found" });
    expect(
      await t.mutation(api.credentials.reveal, {
        auditRevealsKinds: [],
        ref: { credentialId: a.credentialId },
        includePrevious: true,
      }),
    ).toEqual({ value: "renewed supplied credential" });
    const b = await t.mutation(
      api.credentials.create,
      input({ kind: "capped", value: old, ttlMs: 3000 }),
    );
    await t.mutation(api.credentials.replace, {
      ref: { credentialId: b.credentialId },
      value: "capped replacement credential",
      ttlMs: 10_000,
      graceMs: 5000,
    });
    expect(
      await t.mutation(api.credentials.reveal, {
        auditRevealsKinds: [],
        ref: { credentialId: b.credentialId },
        includePrevious: true,
      }),
    ).toEqual({
      value: "capped replacement credential",
      previous: { value: old, validUntilAt: START + 4000 },
    });
    vi.setSystemTime(START + 4000);
    expect(
      await t.mutation(api.credentials.verify, { kind: "capped", value: old, owner: "tenant" }),
    ).toEqual({ ok: false, reason: "expired" });
  });
  it("resolves a credential ID reference only for the kind it names", async () => {
    const t = setupTest();
    const a = await t.mutation(
      api.credentials.create,
      input({ storage: "encrypted", kind: "credential" }),
    );
    await expectVaultError(
      t.mutation(api.credentials.reveal, {
        auditRevealsKinds: [],
        ref: { credentialId: a.credentialId, kind: "other" },
      }),
      "VAULT_NOT_FOUND",
    );
    await expectVaultError(
      t.mutation(api.credentials.revoke, { ref: { credentialId: a.credentialId, kind: "other" } }),
      "VAULT_NOT_FOUND",
    );
    expect(
      await t.mutation(api.credentials.reveal, {
        auditRevealsKinds: [],
        ref: { credentialId: a.credentialId, kind: "credential" },
      }),
    ).toEqual({ value: input().value });
  });
  it("rejects duplicate values across key versions, across owners under global lookup, and against expired previous values", async () => {
    const t = setupTest();
    const old = configureKeys();
    const a = await t.mutation(api.credentials.create, input());
    await expectVaultError(t.mutation(api.credentials.create, input()), "VAULT_DUPLICATE_VALUE");
    vi.stubEnv("VAULT_KEYS", `2:${generateMasterKey()},1:${old}`);
    await expectVaultError(t.mutation(api.credentials.create, input()), "VAULT_DUPLICATE_VALUE");
    await t.mutation(api.credentials.replace, {
      ref: { credentialId: a.credentialId },
      value: "next",
      graceMs: 1,
    });
    vi.setSystemTime(START + 2);
    await expectVaultError(t.mutation(api.credentials.create, input()), "VAULT_DUPLICATE_VALUE");
    await expectVaultError(
      t.mutation(api.credentials.replace, { ref: { credentialId: a.credentialId }, value: "next" }),
      "VAULT_DUPLICATE_VALUE",
    );
    await t.mutation(
      api.credentials.create,
      input({ kind: "global", lookup: "global", value: "y".repeat(32) }),
    );
    await expectVaultError(
      t.mutation(
        api.credentials.create,
        input({ kind: "global", owner: "other", lookup: "global", value: "y".repeat(32) }),
      ),
      "VAULT_DUPLICATE_VALUE",
    );
  });
  it("records immutable kind policy and reserves unique owner/kind/name identities", async () => {
    const t = setupTest();
    const created = await t.mutation(api.credentials.create, input({ name: "primary" }));
    for (const change of [
      { storage: "hashed" as Storage },
      { origin: "generated" as const, value: undefined, lookup: "global" as const },
      { lookup: "global" as const },
    ]) {
      await expectVaultError(
        t.mutation(api.credentials.create, input(change)),
        "VAULT_KIND_CONFLICT",
      );
    }
    await expectVaultError(
      t.mutation(api.credentials.create, input({ name: "primary", value: "other" })),
      "VAULT_DUPLICATE_NAME",
    );
    expect(
      await t.query(api.credentials.get, {
        ref: { owner: "tenant", kind: "shared", name: "primary" },
      }),
    ).toMatchObject({ credentialId: created.credentialId });
    await t.mutation(api.credentials.create, input({ owner: "other", name: "primary" }));
    await expectVaultError(
      t.query(api.credentials.get, { ref: { credentialId: "missing" } }),
      "VAULT_NOT_FOUND",
    );
    await expectVaultError(
      t.query(api.credentials.get, { ref: { owner: "tenant", kind: "shared", name: "missing" } }),
      "VAULT_NOT_FOUND",
    );
  });
  it("releases revoked names and no longer resolves them, keeping the revoke event", async () => {
    const t = setupTest();
    const created = await t.mutation(api.credentials.create, input({ name: "primary" }));
    const ref = { credentialId: created.credentialId };
    await t.mutation(api.credentials.revoke, { ref });
    await t.mutation(api.credentials.revoke, { ref });
    await expectVaultError(
      t.query(api.credentials.get, { ref: { owner: "tenant", kind: "shared", name: "primary" } }),
      "VAULT_NOT_FOUND",
    );
    expect(await t.query(api.credentials.get, { ref })).not.toHaveProperty("name");
    const next = await t.mutation(
      api.credentials.create,
      input({ name: "primary", value: "next" }),
    );
    expect(next.credentialId).not.toBe(created.credentialId);
    const events = await t.query(api.events.list, {
      ref,
      paginationOpts: { numItems: 100, cursor: null },
    });
    expect(events.page.filter((event) => event.type === "revoked")).toHaveLength(1);
  });
  it.each(["reveal", "verify"] as const)(
    "releases an exhausted name through %s",
    async (operation) => {
      const t = setupTest();
      const created = await t.mutation(
        api.credentials.create,
        input({ name: "primary", maxUses: 1 }),
      );
      const ref = { credentialId: created.credentialId };
      if (operation === "reveal")
        await t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref });
      else
        await t.mutation(api.credentials.verify, {
          kind: "shared",
          owner: "tenant",
          value: input().value ?? "",
        });
      expect(await t.query(api.credentials.get, { ref })).toMatchObject({ status: "exhausted" });
      expect(await t.query(api.credentials.get, { ref })).not.toHaveProperty("name");
      await expectVaultError(
        t.query(api.credentials.get, {
          ref: { owner: "tenant", kind: "shared", name: "primary" },
        }),
        "VAULT_NOT_FOUND",
      );
      await t.mutation(api.credentials.create, input({ name: "primary", value: "next" }));
      const events = await t.query(api.events.list, {
        ref,
        paginationOpts: { numItems: 100, cursor: null },
      });
      expect(events.page.filter((event) => event.type === "exhausted")).toHaveLength(1);
    },
  );
  it("audits a reveal when the stored flag or the caller's audited kinds cover the credential's kind", async () => {
    const t = setupTest();
    const created = await t.mutation(
      api.credentials.create,
      input({ storage: "encrypted", auditReveals: false }),
    );
    const ref = { credentialId: created.credentialId };
    const revealed = async () =>
      (
        await t.query(api.events.list, { ref, paginationOpts: { numItems: 100, cursor: null } })
      ).page.filter((event) => event.type === "revealed");
    await t.mutation(api.credentials.reveal, { auditRevealsKinds: ["other"], ref });
    expect(await revealed()).toHaveLength(0);
    await t.mutation(api.credentials.reveal, {
      auditRevealsKinds: ["shared"],
      ref,
      actor: "operator",
    });
    expect(await revealed()).toMatchObject([{ actor: "operator" }]);
    const audited = await t.mutation(
      api.credentials.create,
      input({ kind: "audited", storage: "encrypted", auditReveals: true }),
    );
    await t.mutation(api.credentials.reveal, {
      auditRevealsKinds: [],
      ref: { credentialId: audited.credentialId },
    });
    const events = await t.query(api.events.list, {
      ref: { credentialId: audited.credentialId },
      paginationOpts: { numItems: 100, cursor: null },
    });
    expect(events.page.filter((event) => event.type === "revealed")).toHaveLength(1);
    await expectVaultError(
      t.mutation(api.credentials.reveal, {
        auditRevealsKinds: Array.from({ length: 101 }, (_, index) => `kind${index}`),
        ref,
      }),
      "VAULT_INVALID_ARGUMENT",
    );
    await expectVaultError(
      t.mutation(api.credentials.reveal, { auditRevealsKinds: ["x".repeat(129)], ref }),
      "VAULT_INVALID_ARGUMENT",
    );
  });
  it("rejects an oversized actor on a non-audited reveal, replace and revoke without writing", async () => {
    const t = setupTest();
    const created = await t.mutation(
      api.credentials.create,
      input({ storage: "encrypted", auditReveals: false, maxUses: 5 }),
    );
    const ref = { credentialId: created.credentialId };
    const actor = "x".repeat(257);
    const before = await t.query(api.credentials.get, { ref });
    await expectVaultError(
      t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref, actor }),
      "VAULT_INVALID_ARGUMENT",
    );
    await expectVaultError(
      t.mutation(api.credentials.replace, { ref, value: "replacement", actor }),
      "VAULT_INVALID_ARGUMENT",
    );
    await expectVaultError(
      t.mutation(api.credentials.revoke, { ref, actor }),
      "VAULT_INVALID_ARGUMENT",
    );
    expect(await t.query(api.credentials.get, { ref })).toEqual(before);
  });
  it("throws a non-vault error when a credential has more than two values", async () => {
    const t = setupTest();
    const created = await t.mutation(api.credentials.create, input({ storage: "encrypted" }));
    await t.run(async (ctx) => {
      const credentialId = required(
        ctx.db.normalizeId("credentials", created.credentialId),
        "credential ID",
      );
      for (const valueId of ["extra-1", "extra-2"])
        await ctx.db.insert("values", {
          valueId,
          credentialId,
          state: "previous",
          createdAt: START,
        });
    });
    const error: unknown = await t
      .mutation(api.credentials.revoke, { ref: { credentialId: created.credentialId } })
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(isVaultError(error)).toBe(false);
  });
  it("lists credentials newest first across kinds when kind is omitted", async () => {
    const t = setupTest();
    const ids = [];
    for (const [index, kind] of ["first", "second", "first"].entries()) {
      vi.setSystemTime(START + index);
      ids.push(
        (await t.mutation(api.credentials.create, input({ kind, value: `value ${index}` })))
          .credentialId,
      );
    }
    const page = await t.query(api.credentials.list, {
      owner: "tenant",
      paginationOpts: { numItems: 10, cursor: null },
    });
    expect(page.page.map((credential) => credential.credentialId)).toEqual(ids.toReversed());
  });
  it("rejects expiry exactly at the boundary and renews an expired credential only through replace with new expiry", async () => {
    const t = setupTest();
    const a = await t.mutation(api.credentials.create, input({ ttlMs: 1000 }));
    const ref = { credentialId: a.credentialId };
    vi.setSystemTime(START + 999);
    expect(
      await t.mutation(api.credentials.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toMatchObject({ ok: true });
    expect(await t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref })).toHaveProperty(
      "value",
    );
    vi.setSystemTime(START + 1000);
    expect(
      await t.mutation(api.credentials.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toEqual({ ok: false, reason: "expired" });
    await expectVaultError(
      t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref }),
      "VAULT_INACTIVE",
    );
    await expectVaultError(
      t.mutation(api.credentials.replace, { ref, value: "unrenewed" }),
      "VAULT_INACTIVE",
    );
    await t.mutation(api.credentials.replace, { ref, value: "renewed", ttlMs: 500 });
    expect(await t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref })).toEqual({
      value: "renewed",
    });
    expect(await t.query(api.credentials.get, { ref })).toHaveProperty("expiresAt", START + 1500);
    await t.mutation(api.credentials.replace, { ref, value: "third" });
    expect(await t.query(api.credentials.get, { ref })).toHaveProperty("expiresAt", START + 1500);
    await t.mutation(api.credentials.replace, { ref, value: "fourth", expiresAt: START + 2000 });
    expect(await t.query(api.credentials.get, { ref })).toHaveProperty("expiresAt", START + 2000);
  });
  it("renews an expired active credential after cleanup has deleted its current value", async () => {
    const t = setupTest();
    const created = await t.mutation(api.credentials.create, {
      bytes: undefined,
      hint: true,
      auditReveals: true,
      owner: "tenant",
      kind: "key",
      storage: "both",
      origin: "supplied",
      lookup: "owner",
      value: "old",
      ttlMs: 1,
    });
    const ref = { credentialId: created.credentialId };
    vi.setSystemTime(START + 1);
    await t.mutation(internal.cleanup.run, {});
    await drain(t);
    expect(await t.run((ctx) => ctx.db.query("values").take(1))).toEqual([]);
    await t.mutation(api.credentials.replace, { ref, value: "renewed", ttlMs: 1000, graceMs: 100 });
    expect(
      await t.mutation(api.credentials.reveal, {
        auditRevealsKinds: [],
        ref,
        includePrevious: true,
      }),
    ).toEqual({
      value: "renewed",
    });
    expect(
      await t.mutation(api.credentials.verify, { kind: "key", owner: "tenant", value: "renewed" }),
    ).toMatchObject({ ok: true });
  });
  it("consumes one maxUses limit from verify and reveal and consumes no use on a missing scope", async () => {
    const t = setupTest();
    const a = await t.mutation(api.credentials.create, input({ maxUses: 2, scopes: ["read"] }));
    const ref = { credentialId: a.credentialId };
    expect(
      await t.mutation(api.credentials.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
        requiredScopes: ["write"],
      }),
    ).toEqual({ ok: false, reason: "missing_scope" });
    expect(
      await t.mutation(api.credentials.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toMatchObject({ ok: true, usesLeft: 1 });
    await t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref });
    expect(await t.query(api.credentials.get, { ref })).toMatchObject({
      useCount: 2,
      status: "exhausted",
    });
    expect(
      await t.mutation(api.credentials.verify, {
        kind: "shared",
        value: input().value ?? "",
        owner: "tenant",
      }),
    ).toEqual({ ok: false, reason: "exhausted" });
    await expectVaultError(
      t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref }),
      "VAULT_INACTIVE",
    );
    await expectVaultError(
      t.mutation(api.credentials.replace, { ref, value: "new" }),
      "VAULT_INACTIVE",
    );
    const events = await t.query(api.events.list, {
      ref,
      paginationOpts: { numItems: 100, cursor: null },
    });
    expect(events.page.filter((event) => event.type === "exhausted")).toHaveLength(1);
  });
  it.each(["reveal", "verify"] as const)(
    "serializes two concurrent %s calls for a single-use credential",
    async (operation) => {
      const t = setupTest();
      const a = await t.mutation(api.credentials.create, input({ maxUses: 1 }));
      const call = () =>
        operation === "reveal"
          ? t.mutation(api.credentials.reveal, {
              auditRevealsKinds: [],
              ref: { credentialId: a.credentialId },
            })
          : t.mutation(api.credentials.verify, {
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
    const a = await t.mutation(api.credentials.create, input({ auditReveals: false }));
    const ref = { credentialId: a.credentialId };
    const before = await t.query(api.credentials.get, { ref });
    await t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref });
    expect(await t.query(api.credentials.get, { ref })).toEqual(before);
    expect(
      (
        await t.query(api.events.list, {
          ref,
          paginationOpts: { numItems: 100, cursor: null },
        })
      ).page,
    ).toHaveLength(1);
    const verify = { kind: "shared", owner: "tenant", value: input().value ?? "" };
    await t.mutation(api.credentials.verify, verify);
    vi.setSystemTime(START + 59999);
    await t.mutation(api.credentials.verify, verify);
    expect(await t.query(api.credentials.get, { ref })).toMatchObject({
      lastUsedAt: START,
      updatedAt: START,
      useCount: 0,
    });
    vi.setSystemTime(START + 60000);
    await t.mutation(api.credentials.verify, verify);
    expect(await t.query(api.credentials.get, { ref })).toMatchObject({
      lastUsedAt: START + 60000,
      updatedAt: START,
      useCount: 0,
    });
  });
  it("keeps creation-time generation settings and replaces the single previous value", async () => {
    const t = setupTest();
    const a = await t.mutation(
      api.credentials.create,
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
      api.credentials.create,
      input({ origin: "generated", lookup: "global", value: undefined, prefix: "new_", bytes: 64 }),
    );
    const ref = { credentialId: a.credentialId };
    const b = await t.mutation(api.credentials.replace, { ref, graceMs: 1000 });
    expect(b.value).toMatch(/^old_[A-Za-z0-9_-]{22}$/);
    expect(b.hint).toBeUndefined();
    const c = await t.mutation(api.credentials.replace, { ref, graceMs: 2000 });
    expect(
      await t.mutation(api.credentials.verify, {
        kind: "shared",
        value: required(a.value, "generated value"),
      }),
    ).toEqual({ ok: false, reason: "not_found" });
    expect(
      await t.mutation(api.credentials.reveal, {
        auditRevealsKinds: [],
        ref,
        includePrevious: true,
      }),
    ).toEqual({
      value: c.value,
      previous: { value: b.value, validUntilAt: START + 2000 },
    });
  });
  it("paginates owner metadata and audit events without exposing values, ciphertext or hashes", async () => {
    const t = setupTest();
    const outputs: unknown[] = [];
    for (const kind of ["a", "b"])
      for (let i = 0; i < 3; i++)
        outputs.push(
          await t.mutation(
            api.credentials.create,
            input({ kind, name: `key${i}`, value: `${kind}${i}` }),
          ),
        );
    await t.mutation(api.credentials.create, input({ owner: "other" }));
    let cursor: string | null = null;
    const ids = [];
    do {
      const page: PaginationResult<Credential> = await t.query(api.credentials.list, {
        owner: "tenant",
        paginationOpts: { numItems: 2, cursor },
      });
      outputs.push(page);
      expect(page.page.every((row) => row.owner === "tenant")).toBe(true);
      ids.push(...page.page.map((row) => row.credentialId));
      cursor = page.isDone ? null : page.continueCursor;
    } while (cursor !== null);
    expect(new Set(ids).size).toBe(6);
    const first = required(ids[0], "first credential ID");
    outputs.push(await t.query(api.credentials.get, { ref: { credentialId: first } }));
    const filtered = await t.query(api.credentials.list, {
      owner: "tenant",
      kind: "a",
      paginationOpts: { numItems: 100, cursor: null },
    });
    outputs.push(filtered);
    expect(filtered.page).toHaveLength(3);
    outputs.push(
      await t.query(api.events.list, {
        ref: { owner: "tenant" },
        paginationOpts: { numItems: 2, cursor: null },
      }),
    );
    outputs.push(await t.query(api.keys.getStatus, {}));
    outputs.push(await t.mutation(api.keys.rotate, {}));
    outputs.push(
      await t.mutation(api.credentials.reveal, {
        auditRevealsKinds: [],
        ref: { credentialId: first },
      }),
    );
    outputs.push(
      await t.mutation(api.credentials.replace, { ref: { credentialId: first }, value: "new" }),
    );
    outputs.push(
      await t.mutation(api.credentials.verify, { kind: "b", owner: "tenant", value: "new" }),
    );
    outputs.push(await t.mutation(api.credentials.revoke, { ref: { credentialId: first } }));
    expect(JSON.stringify(outputs)).not.toMatch(/ciphertext|wrappedKey|lookupHash|keyIv/);
  });
  it("reads at most numItems + 1 rows when a page request passes endCursor", async () => {
    const t = setupTest();
    for (let i = 0; i < 5; i++)
      await t.mutation(api.credentials.create, input({ name: `key${i}`, value: `value${i}` }));
    const paginationOpts = { numItems: 1, cursor: null, endCursor: "[]" };
    const credentials = await t.query(api.credentials.list, { owner: "tenant", paginationOpts });
    expect(credentials).toMatchObject({ isDone: false, pageStatus: "SplitRequired" });
    expect(credentials.page).toHaveLength(2);
    const events = await t.query(api.events.list, {
      ref: { owner: "tenant" },
      paginationOpts,
    });
    expect(events.page).toHaveLength(2);
  });
  it.each([
    "not-json",
    "5",
    '{"key":1}',
    '[{"$integer":"x"}]',
    "",
    JSON.stringify(["x".repeat(4096)]),
    JSON.stringify(Array.from({ length: 17 }, () => 1)),
    '[{"key":1}]',
    "[[1]]",
    '["\\ud800"]',
  ])("rejects the malformed page cursor %j with a structured error", async (cursor) => {
    const t = setupTest();
    for (const paginationOpts of [
      { numItems: 10, cursor },
      { numItems: 10, cursor: null, endCursor: cursor },
    ]) {
      await expectVaultError(
        t.query(api.credentials.list, { owner: "tenant", paginationOpts }),
        "VAULT_INVALID_ARGUMENT",
      );
      await expectVaultError(
        t.query(api.events.list, { ref: { owner: "tenant" }, paginationOpts }),
        "VAULT_INVALID_ARGUMENT",
      );
    }
  });
  it.each([undefined, "bad", "1:AA"])(
    "fails every public operation closed for configuration %s",
    async (config) => {
      const t = setupTest();
      vi.stubEnv("VAULT_KEYS", config);
      const ref = { credentialId: "missing" };
      const page = { numItems: 10, cursor: null };
      const calls = [
        t.mutation(api.credentials.create, input()),
        t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref }),
        t.mutation(api.credentials.verify, { kind: "shared", value: "test" }),
        t.mutation(api.credentials.replace, { ref }),
        t.mutation(api.credentials.revoke, { ref }),
        t.query(api.credentials.get, { ref }),
        t.query(api.credentials.list, { owner: "tenant", paginationOpts: page }),
        t.query(api.events.list, { ref, paginationOpts: page }),
        t.query(api.keys.getStatus, {}),
        t.mutation(api.keys.rotate, {}),
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
      t.mutation(api.credentials.create, input(overrides)),
      "VAULT_INVALID_ARGUMENT",
    );
    expect(await t.run((ctx) => ctx.db.query("credentials").take(1))).toEqual([]);
  });
  it("accepts UTF-8, metadata, and generation bounds at their limits", async () => {
    const t = setupTest();
    await t.mutation(
      api.credentials.create,
      input({
        value: "😀".repeat(4096),
        scopes: Array.from({ length: 32 }, (_, i) => `scope${i}`),
        metadata: Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`key${i}`, true])),
      }),
    );
    await t.mutation(
      api.credentials.create,
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
    const a = await t.mutation(api.credentials.create, input());
    const ref = { credentialId: a.credentialId };
    for (const graceMs of [-1, 0.5, Number.NaN])
      await expectVaultError(
        t.mutation(api.credentials.replace, { ref, value: "new", graceMs }),
        "VAULT_INVALID_ARGUMENT",
      );
    await expectVaultError(t.mutation(api.credentials.replace, { ref }), "VAULT_INVALID_ARGUMENT");
    await expectVaultError(
      t.mutation(api.credentials.replace, { ref, value: "" }),
      "VAULT_INVALID_ARGUMENT",
    );
    for (const numItems of [0, 101, 1.5]) {
      await expectVaultError(
        t.query(api.credentials.list, {
          owner: "tenant",
          paginationOpts: { numItems, cursor: null },
        }),
        "VAULT_INVALID_ARGUMENT",
      );
      await expectVaultError(
        t.query(api.events.list, { ref, paginationOpts: { numItems, cursor: null } }),
        "VAULT_INVALID_ARGUMENT",
      );
    }
  });
});
