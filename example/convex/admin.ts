import { paginationOptsValidator, paginationResultValidator } from "convex/server";
import { v } from "convex/values";
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
import { internalMutation, internalQuery } from "./_generated/server.js";
import {
  create as createEntry,
  kindValidator,
  revealKindValidator,
  verifyKindValidator,
  vault,
} from "./vault.js";

const referenceValidator = v.union(
  v.object({ entryId: v.string() }),
  v.object({ owner: v.string(), kind: kindValidator, name: v.string() }),
);
const revealReferenceValidator = v.union(
  v.object({ entryId: v.string() }),
  v.object({ owner: v.string(), kind: revealKindValidator, name: v.string() }),
);

export const create = internalMutation({
  args: {
    kind: kindValidator,
    owner: v.string(),
    value: v.optional(v.string()),
    name: v.optional(v.string()),
    label: v.optional(v.string()),
    scopes: v.optional(v.array(v.string())),
    metadata: v.optional(metadataValidator),
    ...lifecycleFields,
    actor: v.optional(v.string()),
  },
  returns: createResultValidator,
  handler: (ctx, { kind, ...options }) => createEntry(ctx, kind, options),
});
export const reveal = internalMutation({
  args: {
    ref: revealReferenceValidator,
    includePrevious: v.optional(v.boolean()),
    actor: v.optional(v.string()),
  },
  returns: revealResultValidator,
  handler: (ctx, { ref, ...options }) => vault.reveal(ctx, ref, options),
});
export const verify = internalMutation({
  args: {
    kind: verifyKindValidator,
    value: v.string(),
    owner: v.optional(v.string()),
    requiredScopes: v.optional(v.array(v.string())),
  },
  returns: verifyResultValidator,
  handler: (ctx, { kind, value, owner, requiredScopes }) => {
    if (kind === "sharedToken" || kind === "importedKey")
      return vault.verify(ctx, kind, value, { owner: owner ?? "", requiredScopes });
    return vault.verify(ctx, kind, value, { owner, requiredScopes });
  },
});
export const replace = internalMutation({
  args: {
    ref: referenceValidator,
    value: v.optional(v.string()),
    graceMs: v.optional(v.number()),
    ttlMs: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
    actor: v.optional(v.string()),
  },
  returns: replaceResultValidator,
  handler: (ctx, { ref, ...options }) => vault.replace(ctx, ref, options),
});
export const revoke = internalMutation({
  args: { ref: referenceValidator, actor: v.optional(v.string()) },
  returns: v.null(),
  handler: (ctx, { ref, ...options }) => vault.revoke(ctx, ref, options),
});
export const get = internalQuery({
  args: { ref: referenceValidator },
  returns: entryResultValidator,
  handler: (ctx, { ref }) => vault.get(ctx, ref),
});
export const list = internalQuery({
  args: {
    owner: v.string(),
    kind: v.optional(kindValidator),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(entryResultValidator),
  handler: (ctx, options) => vault.list(ctx, options),
});
export const listEvents = internalQuery({
  args: {
    ref: v.union(v.object({ entryId: v.string() }), v.object({ owner: v.string() })),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(eventValidator),
  handler: (ctx, { ref, paginationOpts }) => vault.listEvents(ctx, ref, paginationOpts),
});
export const keyStatus = internalQuery({
  args: {},
  returns: v.object({
    activeVersion: v.number(),
    versions: v.array(
      v.object({ version: v.number(), encrypted: v.boolean(), hashed: v.boolean() }),
    ),
    missingVersions: v.array(v.number()),
    missingVersionsTruncated: v.boolean(),
  }),
  handler: (ctx) => vault.keyStatus(ctx),
});
export const rotateKeys = internalMutation({
  args: {},
  returns: v.null(),
  handler: (ctx) => vault.rotateKeys(ctx),
});
