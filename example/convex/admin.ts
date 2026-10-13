import { paginationOptsValidator, paginationResultValidator } from "convex/server";
import { v } from "convex/values";
import {
  createResultValidator,
  replaceResultValidator,
  revealResultValidator,
  verifyResultValidator,
  credentialResultValidator,
  eventValidator,
  keyStatusResultValidator,
  lifecycleValidator,
  metadataValidator,
} from "@operatornest/convex-vault";
import { internalMutation, internalQuery } from "./_generated/server.js";
import {
  create as createCredential,
  kindValidator,
  revealKindValidator,
  verifyKindValidator,
  vault,
} from "./vault.js";

const referenceValidator = v.union(
  v.object({ credentialId: v.string() }),
  v.object({ owner: v.string(), kind: kindValidator, name: v.string() }),
);
const revealReferenceValidator = v.union(
  v.object({ credentialId: v.string() }),
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
    ...lifecycleValidator.fields,
    actor: v.optional(v.string()),
  },
  returns: createResultValidator,
  handler: (ctx, { kind, ...options }) => createCredential(ctx, kind, options),
});
export const reveal = internalMutation({
  args: {
    ref: revealReferenceValidator,
    includePrevious: v.optional(v.boolean()),
    actor: v.optional(v.string()),
  },
  returns: revealResultValidator,
  handler: (ctx, { ref, ...options }) => vault.credentials.reveal(ctx, { ...options, ref: ref }),
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
      return vault.credentials.verify(ctx, {
        owner: owner ?? "",
        requiredScopes,
        kind,
        value,
      });
    return vault.credentials.verify(ctx, {
      owner,
      requiredScopes,
      kind,
      value,
    });
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
  handler: (ctx, { ref, ...options }) => vault.credentials.replace(ctx, { ...options, ref: ref }),
});
export const revoke = internalMutation({
  args: { ref: referenceValidator, actor: v.optional(v.string()) },
  returns: v.null(),
  handler: (ctx, { ref, ...options }) => vault.credentials.revoke(ctx, { ...options, ref: ref }),
});
export const get = internalQuery({
  args: { ref: referenceValidator },
  returns: credentialResultValidator,
  handler: (ctx, { ref }) => vault.credentials.get(ctx, { ref: ref }),
});
export const list = internalQuery({
  args: {
    owner: v.string(),
    kind: v.optional(kindValidator),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(credentialResultValidator),
  handler: (ctx, options) => vault.credentials.list(ctx, options),
});
export const eventsList = internalQuery({
  args: {
    ref: v.union(v.object({ credentialId: v.string() }), v.object({ owner: v.string() })),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(eventValidator),
  handler: (ctx, { ref, paginationOpts }) =>
    vault.events.list(ctx, { ref: ref, paginationOpts: paginationOpts }),
});
export const keysGetStatus = internalQuery({
  args: {},
  returns: keyStatusResultValidator,
  handler: (ctx) => vault.keys.getStatus(ctx),
});
export const keysRotate = internalMutation({
  args: {},
  returns: v.null(),
  handler: (ctx) => vault.keys.rotate(ctx),
});
