import type { Doc } from "./_generated/dataModel.js";
import type { MutationCtx, QueryCtx } from "./_generated/server.js";
import { env } from "./_generated/server.js";
import { readConfig, masterKey, type Keyring } from "../shared/keyring.js";
import { vaultError } from "../shared/errors.js";
import { boundedString, validateValue } from "../shared/bounds.js";
import { encryptEnvelope, type Envelope, type Identity } from "../shared/envelope.js";
import { lookupHash, generateValue, valueHint, randomId } from "../shared/value.js";
import type { Reference, Credential } from "../shared/validators.js";

export const keyring = (): Keyring => readConfig(env);
export async function findCredential(ctx: QueryCtx, ref: Reference): Promise<Doc<"credentials">> {
  let credential;
  if ("credentialId" in ref) {
    boundedString(ref.credentialId, 128);
    if (ref.kind !== undefined) boundedString(ref.kind, 128);
    const credentialId = ctx.db.normalizeId("credentials", ref.credentialId);
    credential = credentialId === null ? null : await ctx.db.get("credentials", credentialId);
    if (credential && ref.kind !== undefined && credential.kind !== ref.kind) credential = null;
  } else {
    boundedString(ref.owner, 256);
    boundedString(ref.kind, 128);
    boundedString(ref.name, 128);
    credential = await ctx.db
      .query("credentials")
      .withIndex("by_owner_and_kind_and_name", (q) =>
        q.eq("owner", ref.owner).eq("kind", ref.kind).eq("name", ref.name),
      )
      .unique();
  }
  if (!credential) throw vaultError("VAULT_NOT_FOUND");
  return credential;
}
export async function current(
  ctx: QueryCtx,
  credential: Doc<"credentials">,
): Promise<Doc<"values">> {
  const row = await ctx.db
    .query("values")
    .withIndex("by_credentialId_and_state", (q) =>
      q.eq("credentialId", credential._id).eq("state", "current"),
    )
    .unique();
  if (!row) throw vaultError("VAULT_NOT_FOUND");
  return row;
}
export async function projection(
  ctx: QueryCtx,
  credential: Doc<"credentials">,
): Promise<Credential> {
  const { _id, _creationTime, hint: enabled, ...fields } = credential;
  const row = await ctx.db
    .query("values")
    .withIndex("by_credentialId_and_state", (q) => q.eq("credentialId", _id).eq("state", "current"))
    .unique();
  return {
    credentialId: _id,
    ...fields,
    ...(enabled && row?.hint !== undefined ? { hint: row.hint } : {}),
  };
}
export function identity(credential: Doc<"credentials">, row: Doc<"values">): Identity {
  return {
    owner: credential.owner,
    kind: credential.kind,
    credentialId: credential._id,
    valueId: row.valueId,
  };
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
export function requireActive(credential: Doc<"credentials">, now?: number): void {
  if (
    credential.status !== "active" ||
    (now !== undefined && credential.expiresAt !== undefined && now >= credential.expiresAt)
  )
    throw vaultError("VAULT_INACTIVE");
}
export async function event(
  ctx: MutationCtx,
  credential: Doc<"credentials">,
  type: Doc<"events">["type"],
  actor?: string,
): Promise<void> {
  if (actor !== undefined) boundedString(actor, 256);
  await ctx.db.insert("events", {
    credentialId: credential._id,
    owner: credential.owner,
    kind: credential.kind,
    type,
    actor,
    occurredAt: Date.now(),
  });
}
export async function consume(
  ctx: MutationCtx,
  credential: Doc<"credentials">,
  now: number,
  verify: boolean,
  actor?: string,
): Promise<number | undefined> {
  const patch: Partial<Doc<"credentials">> = {};
  let usesLeft;
  if (credential.maxUses !== undefined) {
    const count = credential.useCount + 1;
    usesLeft = Math.max(0, credential.maxUses - count);
    patch.useCount = count;
    patch.updatedAt = now;
    if (usesLeft === 0) {
      patch.status = "exhausted";
      patch.name = undefined;
      await event(ctx, credential, "exhausted", actor);
    }
  }
  if (verify && (credential.lastUsedAt === undefined || now - credential.lastUsedAt >= 60000))
    patch.lastUsedAt = now;
  if (Object.keys(patch).length) await ctx.db.patch("credentials", credential._id, patch);
  return usesLeft;
}
export async function deleteValues(
  ctx: MutationCtx,
  credential: Doc<"credentials">,
): Promise<number> {
  const rows = await ctx.db
    .query("values")
    .withIndex("by_credentialId_and_state", (q) => q.eq("credentialId", credential._id))
    .take(3);
  if (rows.length > 2) throw vaultError("VAULT_INVALID_ARGUMENT");
  for (const row of rows) await ctx.db.delete("values", row._id);
  return rows.length;
}
export async function writeValue(
  ctx: MutationCtx,
  ring: Keyring,
  credential: Doc<"credentials">,
  supplied?: string,
) {
  let value: string;
  if (credential.origin === "generated") {
    if (supplied !== undefined) throw vaultError("VAULT_INVALID_ARGUMENT");
    value = generateValue(credential.prefix, credential.bytes);
  } else {
    if (supplied === undefined) throw vaultError("VAULT_INVALID_ARGUMENT");
    validateValue(supplied, credential.lookup === "global");
    value = supplied;
  }
  const valueId = randomId();
  let hashes: { lookupHash: string; hashVersion: number } | undefined;
  if (credential.storage !== "encrypted") {
    const lookupOwner = credential.lookup === "owner" ? credential.owner : "";
    for (const [version, key] of ring.keys) {
      const hash = await lookupHash(key, credential.kind, lookupOwner, value);
      const duplicate = await ctx.db
        .query("values")
        .withIndex("by_lookupHash", (q) => q.eq("lookupHash", hash))
        .first();
      if (duplicate) throw vaultError("VAULT_DUPLICATE_VALUE");
      if (version === ring.active) hashes = { lookupHash: hash, hashVersion: version };
    }
  }
  const encrypted =
    credential.storage !== "hashed"
      ? await encryptEnvelope(
          ring,
          { owner: credential.owner, kind: credential.kind, credentialId: credential._id, valueId },
          value,
        )
      : {};
  const hint = valueHint(value, credential.hint, credential.prefix);
  await ctx.db.insert("values", {
    valueId,
    credentialId: credential._id,
    state: "current",
    ...encrypted,
    ...hashes,
    hint,
    createdAt: Date.now(),
  });
  return {
    ...(credential.origin === "generated" ? { value } : {}),
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
