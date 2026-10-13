import { convexTest } from "convex-test";
import { componentsGeneric, defineSchema } from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";
import { afterEach, beforeEach, expect, expectTypeOf, it, vi } from "vitest";
import { register } from "../test.js";
import { configureKeys, required, expectVaultError } from "../test-helpers.js";
import { Vault, type VaultReference, type KindOptions } from "./index.js";

const components = componentsGeneric() as ReturnType<typeof componentsGeneric> & {
  vault: ComponentApi;
};
const kinds = {
  provider: { storage: "encrypted", hint: false, auditReveals: true, lookup: "owner" },
  issued: {
    storage: "hashed",
    generate: { prefix: "sk_", bytes: 16 },
    ttlMs: 1000,
    maxUses: 1,
    hint: false,
    auditReveals: true,
  },
  dual: {
    storage: "both",
    generate: { prefix: "wh_", bytes: 32 },
    hint: false,
    auditReveals: false,
  },
  shared: { storage: "hashed", hint: true, auditReveals: true, lookup: "owner" },
  imported: { storage: "both", lookup: "global", hint: false, auditReveals: true },
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
  expectTypeOf<Parameters<typeof vault.credentials.reveal>[1]["ref"]>().toEqualTypeOf<
    VaultReference<"provider" | "dual" | "imported">
  >();
  expectTypeOf<Parameters<typeof vault.credentials.verify>[1]["kind"]>().toEqualTypeOf<
    "issued" | "dual" | "shared" | "imported"
  >();
  expectTypeOf<Parameters<typeof vault.credentials.get>[1]["ref"]>().toEqualTypeOf<
    VaultReference<keyof typeof kinds>
  >();
});
it("registers the component and runs every client method against real component functions", async () => {
  const t = setup();
  const provider = await t.run((ctx) =>
    vault.credentials.create(ctx, {
      owner: "tenant",
      name: "main",
      value: "provider credential",
      kind: "provider",
    }),
  );
  const ref = { credentialId: provider.credentialId, kind: "provider" as const };
  expect(await t.run((ctx) => vault.credentials.reveal(ctx, { ref: ref }))).toEqual({
    value: "provider credential",
  });
  await t.run((ctx) =>
    vault.credentials.replace(ctx, {
      value: "replacement",
      graceMs: 100,
      ref,
    }),
  );
  expect(
    await t.run((ctx) =>
      vault.credentials.reveal(ctx, {
        includePrevious: true,
        ref: {
          owner: "tenant",
          kind: "provider",
          name: "main",
        },
      }),
    ),
  ).toMatchObject({ value: "replacement", previous: { value: "provider credential" } });
  expect(await t.run((ctx) => vault.credentials.get(ctx, { ref: ref }))).toMatchObject({
    storage: "encrypted",
    lookup: "owner",
    name: "main",
  });
  const issued = await t.run((ctx) =>
    vault.credentials.create(ctx, {
      owner: "tenant",
      kind: "issued",
    }),
  );
  expect(issued.value).toMatch(/^sk_[A-Za-z0-9_-]{22}$/);
  expect(
    await t.run((ctx) =>
      vault.credentials.verify(ctx, {
        kind: "issued",
        value: required(issued.value, "issued value"),
      }),
    ),
  ).toMatchObject({
    ok: true,
    usesLeft: 0,
  });
  expect(
    await t.run((ctx) =>
      vault.credentials.get(ctx, { ref: { credentialId: issued.credentialId } }),
    ),
  ).toMatchObject({
    expiresAt: 1700000001000,
    maxUses: 1,
  });
  const dual = await t.run((ctx) =>
    vault.credentials.create(ctx, {
      owner: "tenant",
      kind: "dual",
    }),
  );
  expect(dual.hint).toBeUndefined();
  await t.run((ctx) => vault.credentials.reveal(ctx, { ref: { credentialId: dual.credentialId } }));
  expect(
    await t.run((ctx) =>
      vault.events.list(ctx, {
        ref: { credentialId: dual.credentialId },
        paginationOpts: { numItems: 10, cursor: null },
      }),
    ),
  ).toMatchObject({ page: [{ type: "created" }] });
  const shared = await t.run((ctx) =>
    vault.credentials.create(ctx, {
      owner: "tenant",
      value: "shared test credential",
      kind: "shared",
    }),
  );
  expect(shared.hint).toBe("…tial");
  expect(
    await t.run((ctx) =>
      vault.credentials.verify(ctx, {
        owner: "tenant",
        kind: "shared",
        value: "shared test credential",
      }),
    ),
  ).toMatchObject({ ok: true });
  await t.run((ctx) =>
    vault.credentials.create(ctx, {
      owner: "tenant",
      value: "x".repeat(32),
      kind: "imported",
    }),
  );
  expect(
    await t.run((ctx) =>
      vault.credentials.verify(ctx, { kind: "imported", value: "x".repeat(32) }),
    ),
  ).toMatchObject({
    ok: true,
  });
  expect(
    (
      await t.run((ctx) =>
        vault.credentials.list(ctx, {
          owner: "tenant",
          paginationOpts: { numItems: 10, cursor: null },
        }),
      )
    ).page,
  ).toHaveLength(5);
  expect(
    (
      await t.run((ctx) =>
        vault.credentials.list(ctx, {
          owner: "tenant",
          kind: "issued",
          paginationOpts: { numItems: 10, cursor: null },
        }),
      )
    ).page,
  ).toHaveLength(1);
  await t.run((ctx) => vault.keys.rotate(ctx));
  expect(await t.run((ctx) => vault.keys.getStatus(ctx))).toHaveProperty("activeVersion", 1);
  await t.run((ctx) =>
    vault.credentials.revoke(ctx, {
      actor: "operator",
      ref,
    }),
  );
  expect(await t.run((ctx) => vault.credentials.get(ctx, { ref: ref }))).toHaveProperty(
    "status",
    "revoked",
  );
  expect(
    (
      await t.run((ctx) =>
        vault.events.list(ctx, {
          ref: { owner: "tenant" },
          paginationOpts: { numItems: 100, cursor: null },
        }),
      )
    ).page.some((event) => event.type === "revoked" && event.actor === "operator"),
  ).toBe(true);
});
it("allows create-time defaults to be overridden and does not combine a default TTL with explicit expiry", async () => {
  const t = setup();
  const created = await t.run((ctx) =>
    vault.credentials.create(ctx, {
      owner: "tenant",
      expiresAt: 1700000002e3,
      maxUses: 3,
      kind: "issued",
    }),
  );
  expect(
    await t.run((ctx) =>
      vault.credentials.get(ctx, { ref: { credentialId: created.credentialId } }),
    ),
  ).toMatchObject({
    maxUses: 3,
    expiresAt: 1700000002000,
  });
  const another = await t.run((ctx) =>
    vault.credentials.create(ctx, {
      owner: "tenant",
      ttlMs: 3e3,
      kind: "issued",
    }),
  );
  expect(
    await t.run((ctx) =>
      vault.credentials.get(ctx, { ref: { credentialId: another.credentialId } }),
    ),
  ).toHaveProperty("expiresAt", 1700000003000);
});
it("ignores undeclared fields when forwarding credential arguments", async () => {
  const t = setup();
  const alice = { owner: "alice", kind: "provider", name: "main" } as const;
  const created = await t.run((ctx) =>
    vault.credentials.create(ctx, { ...alice, value: "alice credential" }),
  );
  const bob = await t.run((ctx) =>
    vault.credentials.create(ctx, {
      kind: "provider",
      owner: "bob",
      name: "main",
      value: "bob credential",
    }),
  );
  const extra = { owner: "bob", kind: "dual", credentialId: bob.credentialId, actor: "alice" };
  const revealArgs = { ...extra, ref: alice };
  expect(await t.run((ctx) => vault.credentials.reveal(ctx, revealArgs))).toEqual({
    value: "alice credential",
  });
  const replaceArgs = { ...extra, ref: alice, value: "alice replacement" };
  await t.run((ctx) => vault.credentials.replace(ctx, replaceArgs));
  await t.run((ctx) => vault.credentials.revoke(ctx, revealArgs));
  expect(
    await t.run((ctx) =>
      vault.credentials.get(ctx, { ref: { credentialId: created.credentialId } }),
    ),
  ).toMatchObject({ status: "revoked" });
  expect(
    await t.run((ctx) =>
      vault.credentials.reveal(ctx, { ref: { credentialId: bob.credentialId } }),
    ),
  ).toEqual({ value: "bob credential" });
});
it("fails closed for undeclared kinds and storage-incompatible references at runtime", async () => {
  const t = setup();
  const dynamic = new Vault<Record<string, KindOptions>>(components.vault, {
    kinds: {
      credential: { storage: "encrypted", hint: false, auditReveals: true, lookup: "owner" },
      hash: { storage: "hashed", hint: false, auditReveals: true, lookup: "owner" },
    },
  });
  await expectVaultError(
    t.run((ctx) =>
      dynamic.credentials.create(ctx, {
        owner: "tenant",
        value: "x",
        kind: "missing",
      }),
    ),
    "VAULT_INVALID_ARGUMENT",
  );
  await expectVaultError(
    t.run((ctx) =>
      dynamic.credentials.get(ctx, { ref: { credentialId: "missing", kind: "missing" } }),
    ),
    "VAULT_INVALID_ARGUMENT",
  );
  await expectVaultError(
    t.run((ctx) =>
      dynamic.credentials.list(ctx, {
        owner: "tenant",
        kind: "missing",
        paginationOpts: { numItems: 10, cursor: null },
      }),
    ),
    "VAULT_INVALID_ARGUMENT",
  );
  // Simulate a JavaScript caller mutating options after TypeScript construction.
  const changedKinds = {
    hash: { storage: "both", hint: false, auditReveals: true, lookup: "owner" },
    credential: { storage: "both", lookup: "global", hint: false, auditReveals: true },
  } as const satisfies Record<string, KindOptions>;
  const changed = new Vault(components.vault, { kinds: changedKinds });
  Object.assign(changedKinds.hash, {
    storage: "hashed",
    hint: false,
    auditReveals: true,
    lookup: "owner",
  });
  Object.assign(changedKinds.credential, {
    storage: "encrypted",
    hint: false,
    auditReveals: true,
    lookup: "owner",
  });
  await expectVaultError(
    t.run((ctx) =>
      changed.credentials.reveal(ctx, { ref: { credentialId: "unused", kind: "hash" } }),
    ),
    "VAULT_NOT_REVEALABLE",
  );
  await expectVaultError(
    t.run((ctx) => changed.credentials.verify(ctx, { kind: "credential", value: "unused" })),
    "VAULT_NOT_VERIFIABLE",
  );
});
it("audits a reveal by credential ID without kind when the client's current policy for that kind audits reveals", async () => {
  const t = setup();
  const created = await t.run((ctx) =>
    vault.credentials.create(ctx, { owner: "tenant", kind: "dual" }),
  );
  const ref = { credentialId: created.credentialId };
  const revealed = async () =>
    (
      await t.run((ctx) =>
        vault.events.list(ctx, { ref, paginationOpts: { numItems: 100, cursor: null } }),
      )
    ).page.filter((event) => event.type === "revealed");
  await t.run((ctx) => vault.credentials.reveal(ctx, { ref }));
  expect(await revealed()).toHaveLength(0);
  const audited = new Vault(components.vault, {
    kinds: { ...kinds, dual: { ...kinds.dual, auditReveals: true } },
  });
  await t.run((ctx) => audited.credentials.reveal(ctx, { ref, actor: "operator" }));
  expect(await revealed()).toMatchObject([{ actor: "operator" }]);
});

it.each([
  ["an empty kind name", { "": kinds.provider }],
  ["a 129-character kind name", { ["k".repeat(129)]: kinds.dual }],
  ["a kind name that is not well-formed UTF-16", { "kind\ud800": kinds.dual }],
  [
    "101 audited kinds",
    Object.fromEntries(Array.from({ length: 101 }, (_, index) => [`kind${index}`, kinds.provider])),
  ],
])("rejects %s at construction", async (_, invalidKinds: Record<string, KindOptions>) => {
  await expectVaultError(
    Promise.resolve().then(() => new Vault(components.vault, { kinds: invalidKinds })),
    "VAULT_INVALID_ARGUMENT",
  );
});

it("accepts 100 audited kinds, unlimited unaudited kinds and 128-character kind names", async () => {
  const t = setup();
  const boundary = new Vault<Record<string, KindOptions>>(components.vault, {
    kinds: {
      ...Object.fromEntries(
        Array.from({ length: 99 }, (_, index) => [`audited${index}`, kinds.provider]),
      ),
      ...Object.fromEntries(
        Array.from({ length: 50 }, (_, index) => [`unaudited${index}`, kinds.dual]),
      ),
      ["k".repeat(128)]: kinds.provider,
    },
  });
  const created = await t.run((ctx) =>
    boundary.credentials.create(ctx, { kind: "k".repeat(128), owner: "tenant", value: "secret" }),
  );
  const revealed = await t.run((ctx) =>
    boundary.credentials.reveal(ctx, { ref: { credentialId: created.credentialId } }),
  );
  expect(revealed.value).toBe("secret");
});
