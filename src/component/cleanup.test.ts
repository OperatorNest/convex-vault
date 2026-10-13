import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, internal } from "./_generated/api.js";
import { configureKeys, drain, expectVaultError, required, setupTest } from "../test-helpers.js";

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
      await t.mutation(api.credentials.verify, {
        kind: "both",
        value: required(created.value, "generated value"),
      });
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
  await t.mutation(api.credentials.revoke, {
    ref: { credentialId: required(old[0], "first credential ID") },
  });
  vi.setSystemTime(NOW + 30 * DAY);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("values").take(1000))).toHaveLength(100);
  expect(
    await t.query(api.credentials.get, {
      ref: { credentialId: required(old[0], "first credential ID") },
    }),
  ).toMatchObject({
    status: "revoked",
  });
  vi.setSystemTime(NOW + 31 * DAY);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("credentials").take(1000))).toHaveLength(100);
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
it("a cleanup run after a completed run visits no finished credential and schedules one continuation per remaining phase", async () => {
  const t = setupTest();
  for (let i = 0; i < 180; i++) {
    const created = await t.mutation(api.credentials.create, {
      bytes: 32,
      hint: false,
      auditReveals: false,
      owner: "tenant",
      kind: "key",
      storage: "encrypted",
      origin: "generated",
      lookup: "global",
      ttlMs: i % 3 === 0 ? 1 : undefined,
      maxUses: i % 3 === 1 ? 1 : undefined,
    });
    const ref = { credentialId: created.credentialId };
    if (i % 3 === 1) await t.mutation(api.credentials.reveal, { auditRevealsKinds: [], ref });
    else if (i % 3 === 2) await t.mutation(api.credentials.revoke, { ref });
  }
  vi.setSystemTime(NOW + DAY);
  const scheduledCount = async () =>
    (await t.run((ctx) => ctx.db.system.query("_scheduled_functions").take(1000))).length;
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("values").take(1000))).toEqual([]);
  const credentials = await t.run((ctx) => ctx.db.query("credentials").take(1000));
  expect(credentials.filter((credential) => credential.valuesDeletedAt === undefined)).toEqual([]);
  const before = await scheduledCount();
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect((await scheduledCount()) - before).toBe(6);
});
it("cleanup deletes the values of a renewed credential again after its renewed expiry", async () => {
  const t = setupTest();
  const created = await t.mutation(api.credentials.create, {
    bytes: undefined,
    hint: false,
    auditReveals: false,
    owner: "tenant",
    kind: "key",
    storage: "encrypted",
    origin: "supplied",
    lookup: "owner",
    value: "first value",
    ttlMs: 1,
  });
  const ref = { credentialId: created.credentialId };
  const credential = () =>
    t.run(async (ctx) =>
      required(
        await ctx.db.get(
          "credentials",
          required(ctx.db.normalizeId("credentials", created.credentialId), "credential ID"),
        ),
        "credential",
      ),
    );
  vi.setSystemTime(NOW + 1);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("values").take(1))).toEqual([]);
  expect(await credential()).toHaveProperty("valuesDeletedAt", NOW + 1);
  await t.mutation(api.credentials.replace, { ref, value: "renewed value", ttlMs: 1000 });
  expect(await credential()).not.toHaveProperty("valuesDeletedAt");
  expect(await t.run((ctx) => ctx.db.query("values").take(10))).toHaveLength(1);
  vi.setSystemTime(NOW + 1001);
  await t.mutation(internal.cleanup.run, {});
  await drain(t);
  expect(await t.run((ctx) => ctx.db.query("values").take(1))).toEqual([]);
  expect(await credential()).toHaveProperty("valuesDeletedAt", NOW + 1001);
});
