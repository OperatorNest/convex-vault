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
import { decryptPayload, unwrapDataKey, wrapDataKey } from "../shared/envelope.js";
import { lookupHash } from "../shared/value.js";
import { keyringFingerprint, type Keyring } from "../shared/keyring.js";
import { boundedPage } from "../shared/bounds.js";
import { vaultError } from "../shared/errors.js";
import { keyStatusResultValidator } from "../shared/validators.js";

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
    after = row?.[field];
    if (after === undefined) return { versions, truncated: false };
    versions.push(after);
  }
  const more = await ctx.db
    .query("values")
    .withIndex(field === "keyVersion" ? "by_keyVersion" : "by_hashVersion", (q) =>
      q.gt(field, after),
    )
    .first();
  return { versions, truncated: more !== null };
}
export const getStatus = query({
  args: {},
  returns: keyStatusResultValidator,
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
  ring: Keyring,
  cursor: string | null,
  fingerprint: string,
): Promise<void> {
  if ((await keyringFingerprint(ring)) !== fingerprint) throw vaultError("VAULT_NOT_CONFIGURED");
  // Group both versions of each credential: one event and at most 100 values per batch.
  const page = await paginator(ctx.db, schema)
    .query("credentials")
    .paginate(boundedPage({ numItems: 50, cursor }, 2));
  for (const credential of page.page) {
    const rows = await ctx.db
      .query("values")
      .withIndex("by_credentialId_and_state", (q) => q.eq("credentialId", credential._id))
      .take(3);
    if (rows.length > 2)
      throw new Error("Corrupted vault state: credential has more than two values");
    let rekeyed = false;
    for (const row of rows) {
      if (
        row.keyVersion === undefined ||
        (row.keyVersion === ring.active &&
          (row.hashVersion === undefined || row.hashVersion === ring.active))
      )
        continue;
      const bound = identity(credential, row);
      const encrypted = envelope(row);
      const dataKey = await unwrapDataKey(ring, bound, encrypted);
      let hashes;
      if (credential.storage === "both") {
        const value = await decryptPayload(bound, encrypted, dataKey);
        hashes = {
          lookupHash: await lookupHash(
            ring,
            ring.active,
            credential.kind,
            credential.lookup === "owner" ? credential.owner : "",
            value,
          ),
          hashVersion: ring.active,
        };
      }
      await ctx.db.patch("values", row._id, {
        ...(await wrapDataKey(ring, bound, dataKey)),
        ...hashes,
      });
      rekeyed = true;
    }
    if (rekeyed) await event(ctx, credential, "rekeyed");
  }
  if (!page.isDone)
    await ctx.scheduler.runAfter(0, internal.keys.continueRotation, {
      cursor: page.continueCursor,
      keyringFingerprint: fingerprint,
    });
}
export const rotate = mutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const ring = keyring();
    await rotateBatch(ctx, ring, null, await keyringFingerprint(ring));
    return null;
  },
});
export const continueRotation = internalMutation({
  args: { cursor: v.string(), keyringFingerprint: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await rotateBatch(ctx, keyring(), args.cursor, args.keyringFingerprint);
    return null;
  },
});
