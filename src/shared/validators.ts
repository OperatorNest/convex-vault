import { v, type Infer } from "convex/values";

export const storageValidator = v.union(
  v.literal("encrypted"),
  v.literal("hashed"),
  v.literal("both"),
);
export const originValidator = v.union(v.literal("generated"), v.literal("supplied"));
export const lookupValidator = v.union(v.literal("owner"), v.literal("global"));
export const metadataValidator = v.record(
  v.string(),
  v.union(v.string(), v.number(), v.boolean(), v.null()),
);
export const referenceValidator = v.union(
  v.object({ entryId: v.string(), kind: v.optional(v.string()) }),
  v.object({ owner: v.string(), kind: v.string(), name: v.string() }),
);
export const lifecycleFields = {
  ttlMs: v.optional(v.number()),
  expiresAt: v.optional(v.number()),
  maxUses: v.optional(v.number()),
};
export const entryValidator = v.object({
  entryId: v.string(),
  owner: v.string(),
  kind: v.string(),
  name: v.optional(v.string()),
  label: v.optional(v.string()),
  storage: storageValidator,
  origin: originValidator,
  lookup: lookupValidator,
  prefix: v.optional(v.string()),
  bytes: v.optional(v.number()),
  hint: v.boolean(),
  status: v.union(v.literal("active"), v.literal("revoked"), v.literal("exhausted")),
  scopes: v.array(v.string()),
  metadata: metadataValidator,
  expiresAt: v.optional(v.number()),
  maxUses: v.optional(v.number()),
  useCount: v.number(),
  lastUsedAt: v.optional(v.number()),
  auditReveals: v.boolean(),
  createdAt: v.number(),
  updatedAt: v.number(),
});
export const entryResultValidator = entryValidator
  .omit("hint")
  .extend({ hint: v.optional(v.string()) });
export const eventValidator = v.object({
  entryId: v.string(),
  owner: v.string(),
  kind: v.string(),
  type: v.union(
    v.literal("created"),
    v.literal("revealed"),
    v.literal("replaced"),
    v.literal("revoked"),
    v.literal("exhausted"),
    v.literal("rekeyed"),
  ),
  actor: v.optional(v.string()),
  at: v.number(),
});
export const createResultValidator = v.object({
  entryId: v.string(),
  value: v.optional(v.string()),
  hint: v.optional(v.string()),
});
export const replaceResultValidator = createResultValidator.omit("entryId");
export const revealResultValidator = v.object({
  value: v.string(),
  previous: v.optional(v.object({ value: v.string(), validUntil: v.number() })),
});
export const verifyResultValidator = v.union(
  v.object({
    ok: v.literal(true),
    entryId: v.string(),
    owner: v.string(),
    kind: v.string(),
    scopes: v.array(v.string()),
    metadata: metadataValidator,
    usesLeft: v.optional(v.number()),
  }),
  v.object({
    ok: v.literal(false),
    reason: v.union(
      v.literal("not_found"),
      v.literal("expired"),
      v.literal("exhausted"),
      v.literal("missing_scope"),
    ),
  }),
);
export type Storage = Infer<typeof storageValidator>;
export type Lookup = Infer<typeof lookupValidator>;
export type Reference = Infer<typeof referenceValidator>;
export type Metadata = Infer<typeof metadataValidator>;
export type Entry = Infer<typeof entryResultValidator>;
export type CreateResult = Infer<typeof createResultValidator>;
export type ReplaceResult = Infer<typeof replaceResultValidator>;
export type RevealResult = Infer<typeof revealResultValidator>;
export type VerifyResult = Infer<typeof verifyResultValidator>;
