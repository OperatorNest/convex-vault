import { v } from "convex/values";
import { paginationOptsValidator, paginationResultValidator } from "convex/server";
import { paginator } from "convex-helpers/server/pagination";
import { mutation, query } from "./_generated/server.js";
import schema from "./schema.js";
import {
  keyring,
  findCredential,
  current,
  projection,
  envelope,
  identity,
  requireActive,
  consume,
  event,
  writeValue,
  deleteValues,
  findByValue,
} from "./helpers.js";
import { vaultError } from "../shared/errors.js";
import {
  boundedPage,
  boundedString,
  invalid,
  validateGenerate,
  validateMaxUses,
  validateScopes,
  validateMetadata,
  validateValue,
  expiry,
} from "../shared/bounds.js";
import { decryptEnvelope } from "../shared/envelope.js";
import {
  storageValidator,
  originValidator,
  lookupValidator,
  metadataValidator,
  referenceValidator,
  lifecycleValidator,
  credentialResultValidator,
  createResultValidator,
  replaceResultValidator,
  revealResultValidator,
  verifyResultValidator,
  type VerifyResult,
} from "../shared/validators.js";

export const create = mutation({
  args: {
    owner: v.string(),
    kind: v.string(),
    storage: storageValidator,
    origin: originValidator,
    lookup: lookupValidator,
    name: v.optional(v.string()),
    label: v.optional(v.string()),
    value: v.optional(v.string()),
    prefix: v.optional(v.string()),
    bytes: v.optional(v.number()),
    hint: v.boolean(),
    auditReveals: v.boolean(),
    scopes: v.optional(v.array(v.string())),
    metadata: v.optional(metadataValidator),
    actor: v.optional(v.string()),
    ...lifecycleValidator.fields,
  },
  returns: createResultValidator,
  handler: async (ctx, args) => {
    const ring = keyring();
    const now = Date.now();
    boundedString(args.owner, 256);
    boundedString(args.kind, 128);
    if (args.name !== undefined) boundedString(args.name, 128);
    if (args.label !== undefined) boundedString(args.label, 256);
    if (args.actor !== undefined) boundedString(args.actor, 256);
    const scopes = args.scopes ?? [];
    const metadata = args.metadata ?? {};
    validateScopes(scopes);
    validateMetadata(metadata);
    validateMaxUses(args.maxUses);
    const expiresAt = expiry(args, now);
    if (args.origin === "generated") {
      invalid(args.lookup !== "global" || args.value !== undefined);
      if (args.bytes === undefined) throw vaultError("VAULT_INVALID_ARGUMENT");
      validateGenerate(args.prefix ?? "", args.bytes);
    } else
      invalid(args.prefix !== undefined || args.bytes !== undefined || args.value === undefined);
    const policy = await ctx.db
      .query("kinds")
      .withIndex("by_kind", (q) => q.eq("kind", args.kind))
      .unique();
    if (policy) {
      if (
        policy.storage !== args.storage ||
        policy.origin !== args.origin ||
        policy.lookup !== args.lookup
      )
        throw vaultError("VAULT_KIND_CONFLICT");
    } else
      await ctx.db.insert("kinds", {
        kind: args.kind,
        storage: args.storage,
        origin: args.origin,
        lookup: args.lookup,
        createdAt: now,
      });
    if (args.name !== undefined) {
      const duplicate = await ctx.db
        .query("credentials")
        .withIndex("by_owner_and_kind_and_name", (q) =>
          q.eq("owner", args.owner).eq("kind", args.kind).eq("name", args.name),
        )
        .first();
      if (duplicate) throw vaultError("VAULT_DUPLICATE_NAME");
    }
    const credentialId = await ctx.db.insert("credentials", {
      owner: args.owner,
      kind: args.kind,
      storage: args.storage,
      origin: args.origin,
      lookup: args.lookup,
      name: args.name,
      label: args.label,
      prefix: args.origin === "generated" ? (args.prefix ?? "") : undefined,
      bytes: args.origin === "generated" ? args.bytes : undefined,
      hint: args.hint,
      status: "active",
      scopes,
      metadata,
      expiresAt,
      maxUses: args.maxUses,
      useCount: 0,
      auditReveals: args.auditReveals,
      createdAt: now,
      updatedAt: now,
    });
    const credential = await ctx.db.get("credentials", credentialId);
    if (!credential) throw vaultError("VAULT_NOT_FOUND");
    const result = await writeValue(ctx, ring, credential, args.value);
    await event(ctx, credential, "created", args.actor);
    return { credentialId, ...result };
  },
});
export const reveal = mutation({
  args: {
    ref: referenceValidator,
    includePrevious: v.optional(v.boolean()),
    auditRevealsKinds: v.array(v.string()),
    actor: v.optional(v.string()),
  },
  returns: revealResultValidator,
  handler: async (ctx, args) => {
    const ring = keyring();
    invalid(args.auditRevealsKinds.length > 100);
    for (const kind of args.auditRevealsKinds) boundedString(kind, 128);
    if (args.actor !== undefined) boundedString(args.actor, 256);
    const credential = await findCredential(ctx, args.ref);
    const now = Date.now();
    requireActive(credential, now);
    if (credential.storage === "hashed") throw vaultError("VAULT_NOT_REVEALABLE");
    const row = await current(ctx, credential);
    const value = await decryptEnvelope(ring, identity(credential, row), envelope(row));
    let previous;
    if (args.includePrevious) {
      const old = await ctx.db
        .query("values")
        .withIndex("by_credentialId_and_state", (q) =>
          q.eq("credentialId", credential._id).eq("state", "previous"),
        )
        .unique();
      if (old?.validUntilAt !== undefined && old.validUntilAt > now)
        previous = {
          value: await decryptEnvelope(ring, identity(credential, old), envelope(old)),
          validUntilAt: old.validUntilAt,
        };
    }
    if (credential.auditReveals || args.auditRevealsKinds.includes(credential.kind))
      await event(ctx, credential, "revealed", args.actor);
    await consume(ctx, credential, now, false, args.actor);
    return { value, ...(previous ? { previous } : {}) };
  },
});
export const verify = mutation({
  args: {
    kind: v.string(),
    value: v.string(),
    owner: v.optional(v.string()),
    requiredScopes: v.optional(v.array(v.string())),
  },
  returns: verifyResultValidator,
  handler: async (ctx, args): Promise<VerifyResult> => {
    const ring = keyring();
    boundedString(args.kind, 128);
    validateValue(args.value, false);
    const requiredScopes = args.requiredScopes ?? [];
    validateScopes(requiredScopes);
    const policy = await ctx.db
      .query("kinds")
      .withIndex("by_kind", (q) => q.eq("kind", args.kind))
      .unique();
    if (!policy) return { ok: false, reason: "not_found" };
    if (policy.storage === "encrypted") throw vaultError("VAULT_NOT_VERIFIABLE");
    if (policy.lookup === "owner" && args.owner === undefined)
      throw vaultError("VAULT_INVALID_ARGUMENT");
    if (args.owner !== undefined) boundedString(args.owner, 256);
    const row = await findByValue(
      ctx,
      ring,
      args.kind,
      policy.lookup === "owner" ? (args.owner ?? "") : "",
      args.value,
    );
    if (!row) return { ok: false, reason: "not_found" };
    const credential = await ctx.db.get("credentials", row.credentialId);
    const now = Date.now();
    if (
      !credential ||
      credential.status === "revoked" ||
      credential.kind !== args.kind ||
      (args.owner !== undefined && credential.owner !== args.owner)
    )
      return { ok: false, reason: "not_found" };
    if (credential.status === "exhausted") return { ok: false, reason: "exhausted" };
    if (
      (credential.expiresAt !== undefined && now >= credential.expiresAt) ||
      (row.state === "previous" && (row.validUntilAt === undefined || now >= row.validUntilAt))
    )
      return { ok: false, reason: "expired" };
    if (requiredScopes.some((scope) => !credential.scopes.includes(scope)))
      return { ok: false, reason: "missing_scope" };
    const usesLeft = await consume(ctx, credential, now, true);
    return {
      ok: true,
      credentialId: credential._id,
      owner: credential.owner,
      kind: credential.kind,
      scopes: credential.scopes,
      metadata: credential.metadata,
      ...(usesLeft !== undefined ? { usesLeft } : {}),
    };
  },
});
export const replace = mutation({
  args: {
    ref: referenceValidator,
    value: v.optional(v.string()),
    graceMs: v.optional(v.number()),
    ttlMs: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
    actor: v.optional(v.string()),
  },
  returns: replaceResultValidator,
  handler: async (ctx, args) => {
    const ring = keyring();
    if (args.actor !== undefined) boundedString(args.actor, 256);
    const credential = await findCredential(ctx, args.ref);
    requireActive(credential);
    const now = Date.now();
    const graceMs = args.graceMs ?? 0;
    invalid(!Number.isSafeInteger(graceMs) || graceMs < 0 || !Number.isSafeInteger(now + graceMs));
    const expiresAt = expiry(args, now) ?? credential.expiresAt;
    if (expiresAt !== undefined && expiresAt <= now) throw vaultError("VAULT_INACTIVE");
    const old = await ctx.db
      .query("values")
      .withIndex("by_credentialId_and_state", (q) =>
        q.eq("credentialId", credential._id).eq("state", "current"),
      )
      .unique();
    // Cleanup removes expired payloads before it removes the credential identity.
    if (!old && (credential.expiresAt === undefined || credential.expiresAt > now))
      throw vaultError("VAULT_NOT_FOUND");
    // Probe uniqueness before removing any prior value, including expired grace values.
    const result = await writeValue(ctx, ring, credential, args.value);
    const previous = await ctx.db
      .query("values")
      .withIndex("by_credentialId_and_state", (q) =>
        q.eq("credentialId", credential._id).eq("state", "previous"),
      )
      .unique();
    if (previous) await ctx.db.delete("values", previous._id);
    if (old) {
      const validUntilAt = Math.min(
        now + graceMs,
        credential.expiresAt ?? Number.POSITIVE_INFINITY,
      );
      if (validUntilAt > now)
        await ctx.db.patch("values", old._id, { state: "previous", validUntilAt });
      else await ctx.db.delete("values", old._id);
    }
    await ctx.db.patch("credentials", credential._id, {
      expiresAt,
      updatedAt: now,
      valuesDeletedAt: undefined,
    });
    await event(ctx, credential, "replaced", args.actor);
    return result;
  },
});
export const revoke = mutation({
  args: { ref: referenceValidator, actor: v.optional(v.string()) },
  returns: v.null(),
  handler: async (ctx, args) => {
    keyring();
    if (args.actor !== undefined) boundedString(args.actor, 256);
    const credential = await findCredential(ctx, args.ref);
    if (credential.status === "revoked") return null;
    await deleteValues(ctx, credential);
    const now = Date.now();
    await ctx.db.patch("credentials", credential._id, {
      status: "revoked",
      name: undefined,
      updatedAt: now,
      valuesDeletedAt: now,
    });
    await event(ctx, credential, "revoked", args.actor);
    return null;
  },
});
export const get = query({
  args: { ref: referenceValidator },
  returns: credentialResultValidator,
  handler: async (ctx, args) => {
    keyring();
    return projection(ctx, await findCredential(ctx, args.ref));
  },
});
export const list = query({
  args: {
    owner: v.string(),
    kind: v.optional(v.string()),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(credentialResultValidator),
  handler: async (ctx, args) => {
    keyring();
    boundedString(args.owner, 256);
    if (args.kind !== undefined) boundedString(args.kind, 128);
    const pageRequest = boundedPage(args.paginationOpts, args.kind === undefined ? 4 : 5);
    const credentials = paginator(ctx.db, schema).query("credentials");
    const { kind } = args;
    const page = await (
      kind === undefined
        ? credentials.withIndex("by_owner_and_createdAt", (q) => q.eq("owner", args.owner))
        : credentials.withIndex("by_owner_and_kind_and_createdAt", (q) =>
            q.eq("owner", args.owner).eq("kind", kind),
          )
    )
      .order("desc")
      .paginate(pageRequest);
    const results = [];
    for (const credential of page.page) results.push(await projection(ctx, credential));
    return { ...page, page: results };
  },
});
