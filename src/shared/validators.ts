import { v, type Infer } from "convex/values";

/** Validates a kind's credential value storage: `encrypted`, `hashed` or `both`. */
export const storageValidator = v.union(
  v.literal("encrypted"),
  v.literal("hashed"),
  v.literal("both"),
);
/** Validates whether a credential value was `generated` by the vault or `supplied` by the caller. */
export const originValidator = v.union(v.literal("generated"), v.literal("supplied"));
/** Validates whether verification looks up supplied values per `owner` or across every owner (`global`). */
export const lookupValidator = v.union(v.literal("owner"), v.literal("global"));
/** Validates plaintext credential metadata: a record of string, number, boolean or null values. */
export const metadataValidator = v.record(
  v.string(),
  v.union(v.string(), v.number(), v.boolean(), v.null()),
);
/** Validates a credential reference: `{ credentialId, kind? }` or `{ owner, kind, name }`. */
export const referenceValidator = v.union(
  v.object({ credentialId: v.string(), kind: v.optional(v.string()) }),
  v.object({ owner: v.string(), kind: v.string(), name: v.string() }),
);
/** Validates the optional `ttlMs`, `expiresAt` and `maxUses` lifecycle arguments; spread its `.fields` into function arguments. */
export const lifecycleValidator = v.object({
  ttlMs: v.optional(v.number()),
  expiresAt: v.optional(v.number()),
  maxUses: v.optional(v.number()),
});
/** Validates a credential status: `active`, `revoked` or `exhausted`. */
export const credentialStatusValidator = v.union(
  v.literal("active"),
  v.literal("revoked"),
  v.literal("exhausted"),
);
/** Validates a value state: `current`, or `previous` during grace. */
export const valueStateValidator = v.union(v.literal("current"), v.literal("previous"));
/** Validates the credential operation an audit event records. */
export const eventTypeValidator = v.union(
  v.literal("created"),
  v.literal("revealed"),
  v.literal("replaced"),
  v.literal("revoked"),
  v.literal("exhausted"),
  v.literal("rekeyed"),
);
/** Validates why verification failed: `not_found`, `expired`, `exhausted` or `missing_scope`. */
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
  valuesDeletedAt: v.optional(v.number()),
});
/** Validates the stored credential metadata and current hint that `credentials.get` and `credentials.list` return. */
export const credentialResultValidator = credentialValidator
  .omit("hint", "valuesDeletedAt")
  .extend({ credentialId: v.string(), hint: v.optional(v.string()) });
/** Validates an audit event that `events.list` returns. */
export const eventValidator = v.object({
  credentialId: v.string(),
  owner: v.string(),
  kind: v.string(),
  type: eventTypeValidator,
  actor: v.optional(v.string()),
  occurredAt: v.number(),
});
/** Validates the `credentials.create` result: the credential row ID and any generated plaintext and hint. */
export const createResultValidator = v.object({
  credentialId: v.string(),
  value: v.optional(v.string()),
  hint: v.optional(v.string()),
});
/** Validates the `credentials.replace` result: any generated replacement plaintext and hint. */
export const replaceResultValidator = createResultValidator.omit("credentialId");
/** Validates the `credentials.reveal` result: the current plaintext and any requested previous plaintext. */
export const revealResultValidator = v.object({
  value: v.string(),
  previous: v.optional(v.object({ value: v.string(), validUntilAt: v.number() })),
});
/** Validates the `credentials.verify` result: the verified credential or a failure reason. */
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
/** Validates the `keys.getStatus` result: configured versions and the versions stored values reference. */
export const keyStatusResultValidator = v.object({
  activeVersion: v.number(),
  versions: v.array(v.object({ version: v.number(), encrypted: v.boolean(), hashed: v.boolean() })),
  missingVersions: v.array(v.number()),
  missingVersionsTruncated: v.boolean(),
});
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
/** Reports configured master-key versions and the versions stored values reference. */
export type KeyStatusResult = Infer<typeof keyStatusResultValidator>;

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
