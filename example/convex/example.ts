import { paginationOptsValidator, paginationResultValidator } from "convex/server";
import { ConvexError, v } from "convex/values";
import {
  createResultValidator,
  replaceResultValidator,
  revealResultValidator,
  verifyResultValidator,
  entryResultValidator,
  eventValidator,
  lifecycleFields,
  metadataValidator,
} from "@operatornest/convex-vault";
import { mutation, query, type QueryCtx } from "./_generated/server.js";
import { create as createEntry, kindValidator, revealKindValidator, vault } from "./vault.js";

async function requireOwner(ctx: QueryCtx): Promise<string> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new ConvexError("Not signed in");
  return identity.tokenIdentifier;
}

export const create = mutation({
  args: {
    kind: kindValidator,
    name: v.string(),
    value: v.optional(v.string()),
    label: v.optional(v.string()),
    scopes: v.optional(v.array(v.string())),
    metadata: v.optional(metadataValidator),
    ...lifecycleFields,
  },
  returns: createResultValidator,
  handler: async (ctx, { kind, ...options }) => {
    const owner = await requireOwner(ctx);
    return createEntry(ctx, kind, { ...options, owner });
  },
});
export const reveal = mutation({
  args: { kind: revealKindValidator, name: v.string(), includePrevious: v.optional(v.boolean()) },
  returns: revealResultValidator,
  handler: async (ctx, { includePrevious, ...ref }) => {
    const owner = await requireOwner(ctx);
    return vault.reveal(ctx, { ...ref, owner }, { includePrevious });
  },
});
// Passing owner stops a presented token from consuming another owner's uses.
export const verify = mutation({
  args: {
    kind: v.union(v.literal("sharedToken"), v.literal("importedKey")),
    value: v.string(),
    requiredScopes: v.optional(v.array(v.string())),
  },
  returns: verifyResultValidator,
  handler: async (ctx, { kind, value, requiredScopes }) => {
    const owner = await requireOwner(ctx);
    return vault.verify(ctx, kind, value, { owner, requiredScopes });
  },
});
export const replace = mutation({
  args: {
    kind: kindValidator,
    name: v.string(),
    value: v.optional(v.string()),
    graceMs: v.optional(v.number()),
    ttlMs: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
  },
  returns: replaceResultValidator,
  handler: async (ctx, { kind, name, ...options }) => {
    const owner = await requireOwner(ctx);
    return vault.replace(ctx, { kind, name, owner }, options);
  },
});
export const revoke = mutation({
  args: { kind: kindValidator, name: v.string() },
  returns: v.null(),
  handler: async (ctx, ref) => {
    const owner = await requireOwner(ctx);
    return vault.revoke(ctx, { ...ref, owner });
  },
});
export const get = query({
  args: { kind: kindValidator, name: v.string() },
  returns: entryResultValidator,
  handler: async (ctx, ref) => {
    const owner = await requireOwner(ctx);
    return vault.get(ctx, { ...ref, owner });
  },
});
export const list = query({
  args: { kind: v.optional(kindValidator), paginationOpts: paginationOptsValidator },
  returns: paginationResultValidator(entryResultValidator),
  handler: async (ctx, options) => {
    const owner = await requireOwner(ctx);
    return vault.list(ctx, { ...options, owner });
  },
});
export const listEvents = query({
  args: { paginationOpts: paginationOptsValidator },
  returns: paginationResultValidator(eventValidator),
  handler: async (ctx, { paginationOpts }) => {
    const owner = await requireOwner(ctx);
    return vault.listEvents(ctx, { owner }, paginationOpts);
  },
});
