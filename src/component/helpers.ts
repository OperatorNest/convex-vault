import type { Doc } from "./_generated/dataModel.js";
import type { MutationCtx, QueryCtx } from "./_generated/server.js";
import { env } from "./_generated/server.js";
import { parseKeyring, masterKey, type Keyring } from "../shared/keyring.js";
import { vaultError } from "../shared/errors.js";
import { boundedString, validateValue } from "../shared/bounds.js";
import { encryptEnvelope, type Envelope, type Identity } from "../shared/envelope.js";
import { lookupHash, generateValue, valueHint, randomId } from "../shared/value.js";
import type { Reference, Entry } from "../shared/validators.js";

export const keyring = (): Keyring => parseKeyring(env.VAULT_KEYS);
export async function findEntry(ctx: QueryCtx, ref: Reference): Promise<Doc<"entries">> {
  let entry;
  if ("entryId" in ref) {
    boundedString(ref.entryId, 128);
    if (ref.kind !== undefined) boundedString(ref.kind, 128);
    entry = await ctx.db
      .query("entries")
      .withIndex("by_entryId", (q) => q.eq("entryId", ref.entryId))
      .unique();
    if (entry && ref.kind !== undefined && entry.kind !== ref.kind) entry = null;
  } else {
    boundedString(ref.owner, 256);
    boundedString(ref.kind, 128);
    boundedString(ref.name, 128);
    entry = await ctx.db
      .query("entries")
      .withIndex("by_owner_and_kind_and_name", (q) =>
        q.eq("owner", ref.owner).eq("kind", ref.kind).eq("name", ref.name),
      )
      .unique();
  }
  if (!entry) throw vaultError("VAULT_NOT_FOUND");
  return entry;
}
export async function current(ctx: QueryCtx, entry: Doc<"entries">): Promise<Doc<"values">> {
  const row = await ctx.db
    .query("values")
    .withIndex("by_entry_and_state", (q) => q.eq("entry", entry._id).eq("state", "current"))
    .unique();
  if (!row) throw vaultError("VAULT_NOT_FOUND");
  return row;
}
export async function projection(ctx: QueryCtx, entry: Doc<"entries">): Promise<Entry> {
  const { _id, _creationTime, hint: enabled, ...fields } = entry;
  const row = await ctx.db
    .query("values")
    .withIndex("by_entry_and_state", (q) => q.eq("entry", _id).eq("state", "current"))
    .unique();
  return { ...fields, ...(enabled && row?.hint !== undefined ? { hint: row.hint } : {}) };
}
export function identity(entry: Doc<"entries">, row: Doc<"values">): Identity {
  return { owner: entry.owner, kind: entry.kind, entryId: entry.entryId, valueId: row.valueId };
}
export function envelope(row: Doc<"values">): Envelope {
  const { keyVersion, ciphertext, iv, wrappedKey, keyIv } = row;
  if (
    keyVersion === undefined ||
    ciphertext === undefined ||
    iv === undefined ||
    wrappedKey === undefined ||
    keyIv === undefined
  )
    throw vaultError("VAULT_DECRYPT_FAILED");
  return { keyVersion, ciphertext, iv, wrappedKey, keyIv };
}
export function requireActive(entry: Doc<"entries">, now?: number): void {
  if (
    entry.status !== "active" ||
    (now !== undefined && entry.expiresAt !== undefined && now >= entry.expiresAt)
  )
    throw vaultError("VAULT_INACTIVE");
}
export async function event(
  ctx: MutationCtx,
  entry: Doc<"entries">,
  type: Doc<"events">["type"],
  actor?: string,
): Promise<void> {
  if (actor !== undefined) boundedString(actor, 256);
  await ctx.db.insert("events", {
    entryId: entry.entryId,
    owner: entry.owner,
    kind: entry.kind,
    type,
    actor,
    at: Date.now(),
  });
}
export async function consume(
  ctx: MutationCtx,
  entry: Doc<"entries">,
  now: number,
  verify: boolean,
  actor?: string,
): Promise<number | undefined> {
  const patch: Partial<Doc<"entries">> = {};
  let usesLeft;
  if (entry.maxUses !== undefined) {
    const count = entry.useCount + 1;
    usesLeft = Math.max(0, entry.maxUses - count);
    patch.useCount = count;
    patch.updatedAt = now;
    if (usesLeft === 0) {
      patch.status = "exhausted";
      patch.name = undefined;
      await event(ctx, entry, "exhausted", actor);
    }
  }
  if (verify && (entry.lastUsedAt === undefined || now - entry.lastUsedAt >= 60000))
    patch.lastUsedAt = now;
  if (Object.keys(patch).length) await ctx.db.patch("entries", entry._id, patch);
  return usesLeft;
}
export async function deleteValues(ctx: MutationCtx, entry: Doc<"entries">): Promise<number> {
  const rows = await ctx.db
    .query("values")
    .withIndex("by_entry_and_state", (q) => q.eq("entry", entry._id))
    .take(3);
  if (rows.length > 2) throw vaultError("VAULT_INVALID_ARGUMENT");
  for (const row of rows) await ctx.db.delete("values", row._id);
  return rows.length;
}
export async function writeValue(
  ctx: MutationCtx,
  ring: Keyring,
  entry: Doc<"entries">,
  supplied?: string,
) {
  let value: string;
  if (entry.origin === "generated") {
    if (supplied !== undefined) throw vaultError("VAULT_INVALID_ARGUMENT");
    value = generateValue(entry.prefix, entry.bytes);
  } else {
    if (supplied === undefined) throw vaultError("VAULT_INVALID_ARGUMENT");
    validateValue(supplied, entry.lookup === "global");
    value = supplied;
  }
  const valueId = randomId();
  let hashes: { lookupHash: string; hashVersion: number } | undefined;
  if (entry.storage !== "encrypted") {
    const lookupOwner = entry.lookup === "owner" ? entry.owner : "";
    for (const [version, key] of ring.keys) {
      const hash = await lookupHash(key, entry.kind, lookupOwner, value);
      const duplicate = await ctx.db
        .query("values")
        .withIndex("by_lookupHash", (q) => q.eq("lookupHash", hash))
        .first();
      if (duplicate) throw vaultError("VAULT_DUPLICATE_VALUE");
      if (version === ring.active) hashes = { lookupHash: hash, hashVersion: version };
    }
  }
  const encrypted =
    entry.storage !== "hashed"
      ? await encryptEnvelope(
          ring,
          { owner: entry.owner, kind: entry.kind, entryId: entry.entryId, valueId },
          value,
        )
      : {};
  const hint = valueHint(value, entry.hint, entry.prefix);
  await ctx.db.insert("values", {
    valueId,
    entry: entry._id,
    state: "current",
    ...encrypted,
    ...hashes,
    hint,
    createdAt: Date.now(),
  });
  return {
    ...(entry.origin === "generated" ? { value } : {}),
    ...(hint !== undefined ? { hint } : {}),
  };
}
export async function findByValue(
  ctx: QueryCtx,
  ring: Keyring,
  kind: string,
  owner: string,
  value: string,
): Promise<Doc<"values"> | null> {
  for (const version of ring.keys.keys()) {
    const hash = await lookupHash(masterKey(ring, version), kind, owner, value);
    const row = await ctx.db
      .query("values")
      .withIndex("by_lookupHash", (q) => q.eq("lookupHash", hash))
      .unique();
    if (row) return row;
  }
  return null;
}
