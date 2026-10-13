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
  v.object({ credentialId: v.string(), kind: v.optional(v.string()) }),
  v.object({ owner: v.string(), kind: v.string(), name: v.string() }),
);
export const lifecycleFields = {
  ttlMs: v.optional(v.number()),
  expiresAt: v.optional(v.number()),
  maxUses: v.optional(v.number()),
};
export const credentialStatusValidator = v.union(
  v.literal("active"),
  v.literal("revoked"),
  v.literal("exhausted"),
);
export const valueStateValidator = v.union(v.literal("current"), v.literal("previous"));
export const eventTypeValidator = v.union(
  v.literal("created"),
  v.literal("revealed"),
  v.literal("replaced"),
  v.literal("revoked"),
  v.literal("exhausted"),
  v.literal("rekeyed"),
);
export const verificationFailureReasonValidator = v.union(
  v.literal("not_found"),
  v.literal("expired"),
  v.literal("exhausted"),
  v.literal("missing_scope"),
);
export const credentialValidator = v.object({
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
  status: credentialStatusValidator,
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
export const credentialResultValidator = credentialValidator
  .omit("hint")
  .extend({ credentialId: v.string(), hint: v.optional(v.string()) });
export const eventValidator = v.object({
  credentialId: v.string(),
  owner: v.string(),
  kind: v.string(),
  type: eventTypeValidator,
  actor: v.optional(v.string()),
  occurredAt: v.number(),
});
export const createResultValidator = v.object({
  credentialId: v.string(),
  value: v.optional(v.string()),
  hint: v.optional(v.string()),
});
export const replaceResultValidator = createResultValidator.omit("credentialId");
export const revealResultValidator = v.object({
  value: v.string(),
  previous: v.optional(v.object({ value: v.string(), validUntilAt: v.number() })),
});
export const verifyResultValidator = v.union(
  v.object({
    ok: v.literal(true),
    credentialId: v.string(),
    owner: v.string(),
    kind: v.string(),
    scopes: v.array(v.string()),
    metadata: metadataValidator,
    usesLeft: v.optional(v.number()),
  }),
  v.object({
    ok: v.literal(false),
    reason: verificationFailureReasonValidator,
  }),
);
/** Selects ciphertext, keyed hash or both for credential values. */
export type Storage = Infer<typeof storageValidator>;
/** Selects owner-scoped or global credential value lookup. */
export type Lookup = Infer<typeof lookupValidator>;
/** Identifies a credential by row ID or owner, kind and name. */
export type Reference = Infer<typeof referenceValidator>;
/** Stores caller-supplied plaintext scalar metadata on a credential. */
export type Metadata = Infer<typeof metadataValidator>;
/** Describes stored credential policy, lifecycle and disclosure hint. */
export type Credential = Infer<typeof credentialResultValidator>;
/** Returns a new credential row ID and any generated plaintext and hint. */
export type CreateResult = Infer<typeof createResultValidator>;
/** Returns any generated replacement plaintext and disclosure hint. */
export type ReplaceResult = Infer<typeof replaceResultValidator>;
/** Returns current plaintext and any requested previous plaintext during grace. */
export type RevealResult = Infer<typeof revealResultValidator>;
/** Reports verified credential ownership and scopes or a verification failure. */
export type VerifyResult = Infer<typeof verifyResultValidator>;

/** Distinguishes generated credential values from supplied values. */
export type Origin = Infer<typeof originValidator>;

/** Tracks active credentials and their terminal revoked or exhausted state. */
export type CredentialStatus = Infer<typeof credentialStatusValidator>;

/** Distinguishes the current value from a previous value retained during grace. */
export type ValueState = Infer<typeof valueStateValidator>;

/** Identifies the credential operation recorded by an audit event. */
export type EventType = Infer<typeof eventTypeValidator>;

/** Identifies why a presented credential value did not verify. */
export type VerificationFailureReason = Infer<typeof verificationFailureReasonValidator>;

/** Records a credential operation and its optional authorized actor. */
export type VaultEvent = Infer<typeof eventValidator>;

/** Identifies whether a stored-row page recommends or requires splitting its cursor range. */
export type PageStatus = "SplitRecommended" | "SplitRequired";
