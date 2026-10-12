import { v } from "convex/values";
import { paginationOptsValidator, paginationResultValidator } from "convex/server";
import { paginator } from "convex-helpers/server/pagination";
import { mutation, query } from "./_generated/server.js";
import schema from "./schema.js";
import {
  keyring,
  findEntry,
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
import { randomId } from "../shared/value.js";
import {
  storageValidator,
  originValidator,
  lookupValidator,
  metadataValidator,
  referenceValidator,
  lifecycleFields,
  entryResultValidator,
  eventValidator,
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
    hint: v.optional(v.boolean()),
    auditReveals: v.optional(v.boolean()),
    scopes: v.optional(v.array(v.string())),
    metadata: v.optional(metadataValidator),
    actor: v.optional(v.string()),
    ...lifecycleFields,
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
      validateGenerate(args.prefix ?? "", args.bytes ?? 32);
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
        .query("entries")
        .withIndex("by_owner_and_kind_and_name", (q) =>
          q.eq("owner", args.owner).eq("kind", args.kind).eq("name", args.name),
        )
        .first();
      if (duplicate) throw vaultError("VAULT_DUPLICATE_NAME");
    }
    const entryId = randomId();
    const id = await ctx.db.insert("entries", {
      entryId,
      owner: args.owner,
      kind: args.kind,
      storage: args.storage,
      origin: args.origin,
      lookup: args.lookup,
      name: args.name,
      label: args.label,
      prefix: args.origin === "generated" ? (args.prefix ?? "") : undefined,
      bytes: args.origin === "generated" ? (args.bytes ?? 32) : undefined,
      hint: args.hint ?? args.origin === "generated",
      status: "active",
      scopes,
      metadata,
      expiresAt,
      maxUses: args.maxUses,
      useCount: 0,
      auditReveals: args.auditReveals ?? true,
      createdAt: now,
      updatedAt: now,
    });
    const entry = await ctx.db.get("entries", id);
    if (!entry) throw vaultError("VAULT_NOT_FOUND");
    const result = await writeValue(ctx, ring, entry, args.value);
    await event(ctx, entry, "created", args.actor);
    return { entryId, ...result };
  },
});
export const reveal = mutation({
  args: {
    ref: referenceValidator,
    includePrevious: v.optional(v.boolean()),
    actor: v.optional(v.string()),
  },
  returns: revealResultValidator,
  handler: async (ctx, args) => {
    const ring = keyring();
    const entry = await findEntry(ctx, args.ref);
    const now = Date.now();
    requireActive(entry, now);
    if (entry.storage === "hashed") throw vaultError("VAULT_NOT_REVEALABLE");
    const row = await current(ctx, entry);
    const value = await decryptEnvelope(ring, identity(entry, row), envelope(row));
    let previous;
    if (args.includePrevious) {
      const old = await ctx.db
        .query("values")
        .withIndex("by_entry_and_state", (q) => q.eq("entry", entry._id).eq("state", "previous"))
        .unique();
      if (old?.validUntil !== undefined && old.validUntil > now)
        previous = {
          value: await decryptEnvelope(ring, identity(entry, old), envelope(old)),
          validUntil: old.validUntil,
        };
    }
    if (entry.auditReveals) await event(ctx, entry, "revealed", args.actor);
    await consume(ctx, entry, now, false, args.actor);
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
    const entry = await ctx.db.get("entries", row.entry);
    const now = Date.now();
    if (
      !entry ||
      entry.status === "revoked" ||
      entry.kind !== args.kind ||
      (args.owner !== undefined && entry.owner !== args.owner)
    )
      return { ok: false, reason: "not_found" };
    if (entry.status === "exhausted") return { ok: false, reason: "exhausted" };
    if (
      (entry.expiresAt !== undefined && now >= entry.expiresAt) ||
      (row.state === "previous" && (row.validUntil === undefined || now >= row.validUntil))
    )
      return { ok: false, reason: "expired" };
    if (requiredScopes.some((scope) => !entry.scopes.includes(scope)))
      return { ok: false, reason: "missing_scope" };
    const usesLeft = await consume(ctx, entry, now, true);
    return {
      ok: true,
      entryId: entry.entryId,
      owner: entry.owner,
      kind: entry.kind,
      scopes: entry.scopes,
      metadata: entry.metadata,
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
    const entry = await findEntry(ctx, args.ref);
    requireActive(entry);
    const now = Date.now();
    const graceMs = args.graceMs ?? 0;
    invalid(!Number.isSafeInteger(graceMs) || graceMs < 0 || !Number.isSafeInteger(now + graceMs));
    const expiresAt = expiry(args, now) ?? entry.expiresAt;
    if (expiresAt !== undefined && expiresAt <= now) throw vaultError("VAULT_INACTIVE");
    const old = await ctx.db
      .query("values")
      .withIndex("by_entry_and_state", (q) => q.eq("entry", entry._id).eq("state", "current"))
      .unique();
    // Cleanup removes expired payloads before it removes the entry identity.
    if (!old && (entry.expiresAt === undefined || entry.expiresAt > now))
      throw vaultError("VAULT_NOT_FOUND");
    // Probe uniqueness before removing any prior value, including expired grace values.
    const result = await writeValue(ctx, ring, entry, args.value);
    const previous = await ctx.db
      .query("values")
      .withIndex("by_entry_and_state", (q) => q.eq("entry", entry._id).eq("state", "previous"))
      .unique();
    if (previous) await ctx.db.delete("values", previous._id);
    if (old) {
      const validUntil = Math.min(now + graceMs, entry.expiresAt ?? Number.POSITIVE_INFINITY);
      if (validUntil > now)
        await ctx.db.patch("values", old._id, { state: "previous", validUntil });
      else await ctx.db.delete("values", old._id);
    }
    await ctx.db.patch("entries", entry._id, { expiresAt, updatedAt: now });
    await event(ctx, entry, "replaced", args.actor);
    return result;
  },
});
export const revoke = mutation({
  args: { ref: referenceValidator, actor: v.optional(v.string()) },
  returns: v.null(),
  handler: async (ctx, args) => {
    keyring();
    const entry = await findEntry(ctx, args.ref);
    if (entry.status === "revoked") return null;
    await deleteValues(ctx, entry);
    await ctx.db.patch("entries", entry._id, {
      status: "revoked",
      name: undefined,
      updatedAt: Date.now(),
    });
    await event(ctx, entry, "revoked", args.actor);
    return null;
  },
});
export const get = query({
  args: { ref: referenceValidator },
  returns: entryResultValidator,
  handler: async (ctx, args) => {
    keyring();
    return projection(ctx, await findEntry(ctx, args.ref));
  },
});
export const list = query({
  args: {
    owner: v.string(),
    kind: v.optional(v.string()),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(entryResultValidator),
  handler: async (ctx, args) => {
    keyring();
    boundedString(args.owner, 256);
    if (args.kind !== undefined) boundedString(args.kind, 128);
    const pageRequest = boundedPage(args.paginationOpts);
    const page = await paginator(ctx.db, schema)
      .query("entries")
      .withIndex("by_owner_and_kind_and_createdAt", (q) =>
        args.kind === undefined
          ? q.eq("owner", args.owner)
          : q.eq("owner", args.owner).eq("kind", args.kind),
      )
      .order("desc")
      .paginate(pageRequest);
    const entries = [];
    for (const entry of page.page) entries.push(await projection(ctx, entry));
    return { ...page, page: entries };
  },
});
export const listEvents = query({
  args: {
    ref: v.union(v.object({ entryId: v.string() }), v.object({ owner: v.string() })),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(eventValidator),
  handler: async (ctx, args) => {
    keyring();
    const pageRequest = boundedPage(args.paginationOpts);
    const ref = args.ref;
    if ("entryId" in ref) boundedString(ref.entryId, 128);
    else boundedString(ref.owner, 256);
    const stream = paginator(ctx.db, schema).query("events");
    const page = await (
      "entryId" in ref
        ? stream.withIndex("by_entryId_and_at", (q) => q.eq("entryId", ref.entryId))
        : stream.withIndex("by_owner_and_at", (q) => q.eq("owner", ref.owner))
    )
      .order("desc")
      .paginate(pageRequest);
    return { ...page, page: page.page.map(({ _id, _creationTime, ...fields }) => fields) };
  },
});
