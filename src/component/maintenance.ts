import { v } from "convex/values";
import { paginator } from "convex-helpers/server/pagination";
import {
  query,
  mutation,
  internalMutation,
  type QueryCtx,
  type MutationCtx,
} from "./_generated/server.js";
import { internal } from "./_generated/api.js";
import schema from "./schema.js";
import { keyring, identity, envelope, event } from "./helpers.js";
import { decryptEnvelope, rewrapEnvelope } from "../shared/envelope.js";
import { lookupHash } from "../shared/value.js";
import { keyringFingerprint, masterKey } from "../shared/keyring.js";
import { vaultError } from "../shared/errors.js";

async function referencedVersions(ctx: QueryCtx, field: "keyVersion" | "hashVersion") {
  const versions: number[] = [];
  let after: number | undefined;
  for (let count = 0; count < 100; count++) {
    const row = await ctx.db
      .query("values")
      .withIndex(field === "keyVersion" ? "by_keyVersion" : "by_hashVersion", (q) =>
        q.gt(field, after),
      )
      .first();
    if (!row) return { versions, truncated: false };
    const version = row[field];
    if (version === undefined) throw vaultError("VAULT_INVALID_ARGUMENT");
    versions.push(version);
    after = version;
  }
  const more = await ctx.db
    .query("values")
    .withIndex(field === "keyVersion" ? "by_keyVersion" : "by_hashVersion", (q) =>
      q.gt(field, after),
    )
    .first();
  return { versions, truncated: more !== null };
}
export const keyStatus = query({
  args: {},
  returns: v.object({
    activeVersion: v.number(),
    versions: v.array(
      v.object({ version: v.number(), encrypted: v.boolean(), hashed: v.boolean() }),
    ),
    missingVersions: v.array(v.number()),
    missingVersionsTruncated: v.boolean(),
  }),
  handler: async (ctx) => {
    const ring = keyring();
    const versions = [];
    for (const version of [...ring.keys.keys()].toSorted((a, b) => b - a)) {
      const encrypted = await ctx.db
        .query("values")
        .withIndex("by_keyVersion", (q) => q.eq("keyVersion", version))
        .first();
      const hashed = await ctx.db
        .query("values")
        .withIndex("by_hashVersion", (q) => q.eq("hashVersion", version))
        .first();
      versions.push({ version, encrypted: encrypted !== null, hashed: hashed !== null });
    }
    const encrypted = await referencedVersions(ctx, "keyVersion");
    const hashed = await referencedVersions(ctx, "hashVersion");
    const missingVersions = [...new Set([...encrypted.versions, ...hashed.versions])]
      .filter((version) => !ring.keys.has(version))
      .toSorted((a, b) => a - b);
    return {
      activeVersion: ring.active,
      versions,
      missingVersions,
      missingVersionsTruncated: encrypted.truncated || hashed.truncated,
    };
  },
});
async function rotateBatch(
  ctx: MutationCtx,
  cursor: string | null,
  fingerprint: string,
): Promise<void> {
  const ring = keyring();
  if ((await keyringFingerprint(ring)) !== fingerprint) throw vaultError("VAULT_NOT_CONFIGURED");
  // Group both versions of each entry: one event and at most 100 values per batch.
  const page = await paginator(ctx.db, schema).query("entries").paginate({ numItems: 50, cursor });
  for (const entry of page.page) {
    const rows = await ctx.db
      .query("values")
      .withIndex("by_entry_and_state", (q) => q.eq("entry", entry._id))
      .take(3);
    if (rows.length > 2) throw vaultError("VAULT_INVALID_ARGUMENT");
    let rekeyed = false;
    for (const row of rows) {
      if (
        row.keyVersion === undefined ||
        (row.keyVersion === ring.active &&
          (row.hashVersion === undefined || row.hashVersion === ring.active))
      )
        continue;
      const bound = identity(entry, row);
      const encrypted = envelope(row);
      let hashes;
      if (entry.storage === "both") {
        const value = await decryptEnvelope(ring, bound, encrypted);
        hashes = {
          lookupHash: await lookupHash(
            masterKey(ring, ring.active),
            entry.kind,
            entry.lookup === "owner" ? entry.owner : "",
            value,
          ),
          hashVersion: ring.active,
        };
      }
      await ctx.db.patch("values", row._id, {
        ...(await rewrapEnvelope(ring, bound, encrypted)),
        ...hashes,
      });
      rekeyed = true;
    }
    if (rekeyed) await event(ctx, entry, "rekeyed");
  }
  if (!page.isDone)
    await ctx.scheduler.runAfter(0, internal.maintenance.continueRotation, {
      cursor: page.continueCursor,
      keyringFingerprint: fingerprint,
    });
}
export const rotateKeys = mutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    await rotateBatch(ctx, null, await keyringFingerprint(keyring()));
    return null;
  },
});
export const continueRotation = internalMutation({
  args: { cursor: v.string(), keyringFingerprint: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await rotateBatch(ctx, args.cursor, args.keyringFingerprint);
    return null;
  },
});
