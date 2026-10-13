import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, internal } from "./_generated/api.js";
import { configureKeys, drain, expectVaultError, required, setupTest } from "../test-helpers.js";
import { generateMasterKey, keyringFingerprint, readConfig } from "../shared/keyring.js";
import type { Storage } from "../shared/validators.js";

const NOW = 1700000000000;
const DAY = 86400000;
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  configureKeys();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

it("rotates across batches, rewraps each both-storage credential once, and keeps hashed-storage values verifiable", async () => {
  const t = setupTest();
  const old = configureKeys();
  const credentials = [];
  for (let i = 0; i < 105; i++) {
    const storage: Storage = i % 3 === 0 ? "hashed" : i % 3 === 1 ? "both" : "encrypted";
    const created = await t.mutation(api.credentials.create, {
      bytes: 32,
      hint: true,
      auditReveals: true,
      owner: "tenant",
      kind: storage,
      storage,
      origin: "generated",
      lookup: "global",
    });
    const ref = { credentialId: created.credentialId };
    const second = await t.mutation(api.credentials.replace, { ref, graceMs: 100000 });
    credentials.push({
      storage,
      credentialId: created.credentialId,
      previous: required(created.value),
      value: required(second.value),
    });
  }
  const before = await t.run((ctx) => ctx.db.query("values").take(1000));
  vi.stubEnv("VAULT_KEYS", `2:${generateMasterKey()},1:${old}`);
  expect(await t.query(api.keys.getStatus, {})).toMatchObject({
    activeVersion: 2,
    versions: [
      { version: 2, encrypted: false, hashed: false },
      { version: 1, encrypted: true, hashed: true },
    ],
  });
  await t.mutation(api.keys.rotate, {});
  await drain(t);
  const after = await t.run((ctx) => ctx.db.query("values").take(1000));
  expect(after).toHaveLength(210);
  expect(after.filter((row) => row.keyVersion === 1)).toHaveLength(0);
  expect(after.filter((row) => row.hashVersion === 1)).toHaveLength(70);
  for (const row of after.filter((value) => value.keyVersion !== undefined)) {
    const prior = required(before.find((value) => value._id === row._id));
    expect(row.ciphertext).toBe(prior.ciphertext);
    expect(row.iv).toBe(prior.iv);
    expect(row.wrappedKey).not.toBe(prior.wrappedKey);
  }
  for (const credential of credentials) {
    const ref = { credentialId: credential.credentialId };
    if (credential.storage !== "hashed")
      expect(
        await t.mutation(api.credentials.reveal, { ref, includePrevious: true }),
      ).toMatchObject({
        value: credential.value,
        previous: { value: credential.previous },
      });
    if (credential.storage !== "encrypted") {
      for (const value of [credential.value, credential.previous])
        expect(
          await t.mutation(api.credentials.verify, { kind: credential.storage, value }),
        ).toMatchObject({ ok: true, credentialId: credential.credentialId });
    }
    const events = await t.query(api.events.list, {
      ref,
      paginationOpts: { numItems: 100, cursor: null },
    });
    expect(events.page.filter((event) => event.type === "rekeyed")).toHaveLength(
      credential.storage === "hashed" ? 0 : 1,
    );
  }
  await t.mutation(api.keys.rotate, {});
  await drain(t);
  expect(
    (await t.run((ctx) => ctx.db.query("events").withIndex("by_occurredAt").take(1000))).filter(
      (event) => event.type === "rekeyed",
    ),
  ).toHaveLength(70);
  vi.stubEnv("VAULT_KEYS", `2:${generateMasterKey()}`);
  expect(await t.query(api.keys.getStatus, {})).toMatchObject({
    missingVersions: [1],
    missingVersionsTruncated: false,
  });
});
it("reports all missing references in a bounded version scan and signals truncation", async () => {
  const t = setupTest();
  const created = await t.mutation(api.credentials.create, {
    bytes: 32,
    hint: true,
    auditReveals: true,
    owner: "tenant",
    kind: "hashed",
    storage: "hashed",
    origin: "generated",
    lookup: "global",
  });
  await t.run(async (ctx) => {
    const credential = required(
      await ctx.db.get(
        "credentials",
        required(ctx.db.normalizeId("credentials", created.credentialId)),
      ),
    );
    for (let version = 2; version <= 102; version++)
      await ctx.db.insert("values", {
        credentialId: credential._id,
        valueId: `synthetic-${version}`,
        state: "previous",
        hashVersion: version,
        createdAt: NOW,
      });
  });
  const status = await t.query(api.keys.getStatus, {});
  expect(status.missingVersions).toHaveLength(99);
  expect(status.missingVersionsTruncated).toBe(true);
});
it("rotation fails closed when an old master key is missing or configuration changes mid-job", async () => {
  const t = setupTest();
  await t.mutation(api.credentials.create, {
    bytes: 32,
    hint: true,
    auditReveals: true,
    owner: "tenant",
    kind: "encrypted",
    storage: "encrypted",
    origin: "generated",
    lookup: "global",
  });
  vi.stubEnv("VAULT_KEYS", `2:${generateMasterKey()}`);
  await expectVaultError(t.mutation(api.keys.rotate, {}), "VAULT_NOT_CONFIGURED");
  await expectVaultError(
    t.mutation(internal.keys.continueRotation, {
      cursor: "unused",
      keyringFingerprint: "unused",
    }),
    "VAULT_NOT_CONFIGURED",
  );
});
it("rotation continuation stops when any key changes, including an inactive key with the same version", async () => {
  const t = setupTest();
  const old = configureKeys();
  for (let i = 0; i < 51; i++)
    await t.mutation(api.credentials.create, {
      bytes: 32,
      hint: true,
      auditReveals: true,
      owner: "tenant",
      kind: "encrypted",
      storage: "encrypted",
      origin: "generated",
      lookup: "global",
    });
  const keys = `2:${generateMasterKey()},1:${old}`;
  vi.stubEnv("VAULT_KEYS", keys);
  await t.mutation(api.keys.rotate, {});
  const [scheduled] = await t.run((ctx) => ctx.db.system.query("_scheduled_functions").take(2));
  const args = required(scheduled).args[0] as { cursor: string; keyringFingerprint: string };
  expect(args.keyringFingerprint).toBe(await keyringFingerprint(readConfig({ VAULT_KEYS: keys })));
  vi.stubEnv("VAULT_KEYS", `2:${generateMasterKey()},1:${old}`);
  await expectVaultError(t.mutation(internal.keys.continueRotation, args), "VAULT_NOT_CONFIGURED");
  vi.stubEnv("VAULT_KEYS", `2:${keys.slice(2, keys.indexOf(","))},1:${generateMasterKey()}`);
  await expectVaultError(t.mutation(internal.keys.continueRotation, args), "VAULT_NOT_CONFIGURED");
  vi.stubEnv("VAULT_KEYS", keys);
  await t.mutation(internal.keys.continueRotation, args);
  const values = await t.run((ctx) => ctx.db.query("values").take(100));
  expect(values.filter((row) => row.keyVersion === 2)).toHaveLength(51);
});
it("cleanup deletes values of revoked and exhausted credentials, past-grace values, credentials past retention and old events across batches", async () => {
  const t = setupTest();
  const keep: string[] = [];
  const drop: string[] = [];
  for (let i = 0; i < 110; i++) {
    const created = await t.mutation(api.credentials.create, {
      bytes: 32,
      hint: true,
      auditReveals: true,
      owner: "tenant",
      kind: "both",
      storage: "both",
      origin: "generated",
      lookup: "global",
      ttlMs: i % 5 === 1 ? 1 : undefined,
      maxUses: i % 5 === 2 ? 1 : undefined,
    });
    const ref = { credentialId: created.credentialId };
    if (i % 5 === 0) {
      await t.mutation(api.credentials.revoke, { ref });
      drop.push(created.credentialId);
    } else if (i % 5 === 1) drop.push(created.credentialId);
    else if (i % 5 === 2) {
      await t.mutation(api.credentials.verify, { kind: "both", value: required(created.value) });
      drop.push(created.credentialId);
    } else {
      const graceMs = i % 5 === 3 ? 1 : 100 * DAY;
      await t.mutation(api.credentials.replace, { ref, graceMs });
      keep.push(created.credentialId);
    }
  }
  vi.setSystemTime(NOW + 2);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  const rows = await t.run((ctx) => ctx.db.query("values").take(1000));
  expect(rows).toHaveLength(66);
  expect(rows.filter((row) => row.state === "previous")).toHaveLength(22);
  expect(await t.run((ctx) => ctx.db.query("credentials").take(1000))).toHaveLength(110);
  expect(await t.run((ctx) => ctx.db.query("events").take(1000))).not.toHaveLength(0);
  vi.setSystemTime(NOW + 30 * DAY - 1);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("credentials").take(1000))).toHaveLength(110);
  vi.setSystemTime(NOW + 30 * DAY + 1);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  const retained = await t.run((ctx) => ctx.db.query("credentials").take(1000));
  expect(retained.map((credential) => credential._id).toSorted()).toEqual(keep.toSorted());
  for (const credentialId of drop)
    await expectVaultError(
      t.query(api.credentials.get, { ref: { credentialId } }),
      "VAULT_NOT_FOUND",
    );
  vi.setSystemTime(NOW + 90 * DAY);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  const atBoundary = await t.run((ctx) => ctx.db.query("events").take(1000));
  expect(atBoundary.length).toBeGreaterThan(100);
  vi.setSystemTime(NOW + 90 * DAY + 1);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("events").take(1000))).toEqual([]);
  expect(await t.run((ctx) => ctx.db.query("credentials").take(1000))).toHaveLength(44);
  expect(await t.run((ctx) => ctx.db.query("kinds").take(1000))).toHaveLength(1);
});
it("cleanup keeps credentials 30 days after updatedAt, never deletes active credentials, and handles a full batch of previous values", async () => {
  const t = setupTest();
  const old = [];
  for (let i = 0; i < 101; i++) {
    const created = await t.mutation(api.credentials.create, {
      bytes: 32,
      hint: true,
      auditReveals: true,
      owner: "tenant",
      kind: "key",
      storage: "encrypted",
      origin: "generated",
      lookup: "global",
    });
    await t.mutation(api.credentials.replace, {
      ref: { credentialId: created.credentialId },
      graceMs: 1,
    });
    old.push(created.credentialId);
  }
  vi.setSystemTime(NOW + DAY);
  await t.mutation(api.credentials.revoke, { ref: { credentialId: required(old[0]) } });
  vi.setSystemTime(NOW + 30 * DAY);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("values").take(1000))).toHaveLength(100);
  expect(
    await t.query(api.credentials.get, { ref: { credentialId: required(old[0]) } }),
  ).toMatchObject({
    status: "revoked",
  });
  vi.setSystemTime(NOW + 31 * DAY);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("credentials").take(1000))).toHaveLength(100);
});
it("rejects swapping encrypted material between rows and stores no plaintext or master keys", async () => {
  const t = setupTest();
  const key = configureKeys();
  const credentials = ["first-test-plaintext-credential", "second-test-plaintext-credential"];
  const ids = [];
  for (const value of credentials)
    ids.push(
      (
        await t.mutation(api.credentials.create, {
          bytes: undefined,
          hint: true,
          auditReveals: true,
          owner: "tenant",
          kind: "both",
          storage: "both",
          origin: "supplied",
          lookup: "owner",
          value,
        })
      ).credentialId,
    );
  const snapshot = await t.run(async (ctx) => ({
    credentials: await ctx.db.query("credentials").take(100),
    values: await ctx.db.query("values").take(100),
    events: await ctx.db.query("events").take(100),
    kinds: await ctx.db.query("kinds").take(100),
  }));
  const json = JSON.stringify(snapshot);
  for (const credential of [...credentials, key]) expect(json).not.toContain(credential);
  const rows = snapshot.values;
  const a = required(rows[0]);
  const b = required(rows[1]);
  for (const field of ["ciphertext", "wrappedKey"] as const) {
    await t.run(async (ctx) => {
      await ctx.db.patch("values", a._id, { [field]: b[field] });
      await ctx.db.patch("values", b._id, { [field]: a[field] });
    });
    for (const credentialId of ids)
      await expectVaultError(
        t.mutation(api.credentials.reveal, { ref: { credentialId } }),
        "VAULT_DECRYPT_FAILED",
      );
    await t.run(async (ctx) => {
      await ctx.db.patch("values", a._id, { [field]: a[field] });
      await ctx.db.patch("values", b._id, { [field]: b[field] });
    });
  }
});

it("cleanup keeps an expired credential 30 days after expiry, not after its last update", async () => {
  const t = setupTest();
  const created = await t.mutation(api.credentials.create, {
    bytes: undefined,
    hint: true,
    auditReveals: true,
    owner: "tenant",
    kind: "key",
    storage: "encrypted",
    origin: "supplied",
    lookup: "owner",
    name: "primary",
    value: "long lived value",
    ttlMs: 60 * DAY,
  });
  const ref = { credentialId: created.credentialId };
  vi.setSystemTime(NOW + 60 * DAY + 1);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("values").take(1))).toEqual([]);
  expect(await t.query(api.credentials.get, { ref })).toMatchObject({ name: "primary" });
  vi.setSystemTime(NOW + 90 * DAY - 1);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.query(api.credentials.get, { ref })).toMatchObject({ status: "active" });
  vi.setSystemTime(NOW + 90 * DAY);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  await expectVaultError(t.query(api.credentials.get, { ref }), "VAULT_NOT_FOUND");
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
  vi.setSystemTime(NOW + 1);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("values").take(1))).toEqual([]);
  await t.mutation(api.credentials.replace, { ref, value: "renewed", ttlMs: 1000, graceMs: 100 });
  expect(await t.mutation(api.credentials.reveal, { ref, includePrevious: true })).toEqual({
    value: "renewed",
  });
  expect(
    await t.mutation(api.credentials.verify, { kind: "key", owner: "tenant", value: "renewed" }),
  ).toMatchObject({ ok: true });
});
