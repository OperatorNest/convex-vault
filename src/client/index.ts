import type {
  GenericActionCtx,
  GenericDataModel,
  GenericMutationCtx,
  GenericQueryCtx,
  PaginationOptions,
} from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";
import { boundedString, validateGenerate } from "../shared/bounds.js";
import { vaultError } from "../shared/errors.js";
import type { Storage, Lookup, Metadata } from "../shared/validators.js";
export { isVaultError, VAULT_ERROR_CODES } from "../shared/errors.js";
export type { VaultErrorCode, VaultErrorData } from "../shared/errors.js";
export { generateMasterKey } from "../shared/keyring.js";
export {
  storageValidator,
  originValidator,
  lookupValidator,
  metadataValidator,
  referenceValidator,
  lifecycleValidator,
  credentialStatusValidator,
  valueStateValidator,
  eventTypeValidator,
  verificationFailureReasonValidator,
  credentialResultValidator,
  eventValidator,
  createResultValidator,
  replaceResultValidator,
  revealResultValidator,
  verifyResultValidator,
  keyStatusResultValidator,
} from "../shared/validators.js";
export type {
  Storage,
  Lookup,
  Reference,
  Metadata,
  Credential,
  CreateResult,
  ReplaceResult,
  RevealResult,
  VerifyResult,
  KeyStatusResult,
  Origin,
  CredentialStatus,
  ValueState,
  EventType,
  VerificationFailureReason,
  VaultEvent,
  PageStatus,
} from "../shared/validators.js";

/** Defines a credential kind's storage, lookup, generation and disclosure policy. */
export type KindOptions = {
  storage: Storage;
  hint: boolean;
  auditReveals: boolean;
  ttlMs?: number;
  maxUses?: number;
} & (
  | { generate: { prefix?: string; bytes: number }; lookup?: never }
  | { generate?: never; lookup: Lookup }
);
/** Configures the credential kinds available to a vault client. */
export type VaultOptions<K extends Record<string, KindOptions> = Record<string, KindOptions>> = {
  kinds: K;
};
/** Supplies ownership, metadata and lifecycle limits when creating a credential. */
export type CreateOptions = {
  owner: string;
  name?: string;
  label?: string;
  scopes?: string[];
  metadata?: Metadata;
  ttlMs?: number;
  expiresAt?: number;
  maxUses?: number;
  actor?: string;
};
/** Supplies a replacement value, grace period and optional renewed expiry. */
export type ReplaceOptions = {
  value?: string;
  graceMs?: number;
  ttlMs?: number;
  expiresAt?: number;
  actor?: string;
};
/** Requests a previous value during grace and identifies the reveal actor. */
export type RevealOptions = { includePrevious?: boolean; actor?: string };
/** Restricts verification to an owner and required scopes. */
export type VerifyOptions = { owner?: string; requiredScopes?: string[] };
// shared-block:begin
/** Runs component queries; app queries, mutations and actions provide it. */
export type QueryContext = Pick<GenericQueryCtx<GenericDataModel>, "runQuery">;
/** Runs component mutations; app mutations and actions provide it. */
export type MutationContext = Pick<GenericMutationCtx<GenericDataModel>, "runMutation">;
/** Runs component actions; app actions provide it. */
export type ActionContext = Pick<GenericActionCtx<GenericDataModel>, "runAction">;
// shared-block:end

type KindName<K> = Extract<keyof K, string>;
type Allowed<K, S extends Storage> = {
  [P in KindName<K>]: K[P] extends { storage: S } ? P : never;
}[KindName<K>];
/** Identifies a credential by its row ID or its owner, kind and name. */
export type VaultReference<K extends string = string> =
  | { credentialId: string; kind?: K }
  | { owner: string; kind: K; name: string };
type CreateFor<C> = CreateOptions &
  (C extends { generate: object } ? { value?: never } : { value: string });
type VerifyFor<C> = C extends { generate: object } | { lookup: "global" }
  ? VerifyOptions
  : VerifyOptions & { owner: string };

function requireKind(options: VaultOptions, name: string): KindOptions {
  const policy = options.kinds[name];
  if (!policy) throw vaultError("VAULT_INVALID_ARGUMENT");
  if (
    typeof policy.hint !== "boolean" ||
    typeof policy.auditReveals !== "boolean" ||
    (!policy.generate && policy.lookup === undefined)
  )
    throw vaultError("VAULT_INVALID_ARGUMENT");
  if (policy.generate) validateGenerate(policy.generate.prefix ?? "", policy.generate.bytes);
  return policy;
}
function validateReference(options: VaultOptions, ref: VaultReference) {
  if (ref.kind !== undefined) requireKind(options, ref.kind);
  return "credentialId" in ref
    ? { credentialId: ref.credentialId, kind: ref.kind }
    : { owner: ref.owner, kind: ref.kind, name: ref.name };
}

/** Calls credential, key and audit-event operations after app authorization. */
export class Vault<const K extends Record<string, KindOptions> = Record<string, KindOptions>> {
  private readonly options: VaultOptions<K> | VaultOptions<Record<string, never>>;
  /** Binds the component and its app-defined credential kinds to this client. */
  constructor(
    private readonly component: ComponentApi,
    options?: VaultOptions<K>,
  ) {
    this.options = options ?? { kinds: {} };
    const kinds = Object.entries(this.options.kinds);
    for (const [kind] of kinds) boundedString(kind, 128);
    if (kinds.filter(([, policy]) => policy.auditReveals).length > 100)
      throw vaultError("VAULT_INVALID_ARGUMENT");
  }
  /** Creates, reveals, verifies, replaces, revokes, reads and lists encrypted credentials. */
  readonly credentials = {
    /** Creates a credential and returns plaintext only for a generated kind. */
    create: <N extends KindName<K>>(ctx: MutationContext, args: { kind: N } & CreateFor<K[N]>) => {
      const policy = requireKind(this.options, args.kind);
      return ctx.runMutation(this.component.credentials.create, {
        owner: args.owner,
        kind: args.kind,
        value: args.value,
        name: args.name,
        label: args.label,
        scopes: args.scopes,
        metadata: args.metadata,
        expiresAt: args.expiresAt,
        actor: args.actor,
        storage: policy.storage,
        origin: policy.generate ? "generated" : "supplied",
        lookup: policy.generate ? "global" : policy.lookup,
        prefix: policy.generate?.prefix,
        bytes: policy.generate?.bytes,
        hint: policy.hint,
        auditReveals: policy.auditReveals,
        ttlMs: args.expiresAt === undefined ? (args.ttlMs ?? policy.ttlMs) : args.ttlMs,
        maxUses: args.maxUses ?? policy.maxUses,
      });
    },
    /** Reveals the current plaintext, optionally the previous plaintext during grace, and audits it when the kind's current or stored policy sets `auditReveals`. */
    reveal: (
      ctx: MutationContext,
      args: { ref: VaultReference<Allowed<K, "encrypted" | "both">> } & RevealOptions,
    ) => {
      if (
        args.ref.kind !== undefined &&
        requireKind(this.options, args.ref.kind).storage === "hashed"
      )
        throw vaultError("VAULT_NOT_REVEALABLE");
      return ctx.runMutation(this.component.credentials.reveal, {
        ref: validateReference(this.options, args.ref),
        includePrevious: args.includePrevious,
        auditRevealsKinds: Object.entries(this.options.kinds)
          .filter(([, policy]) => policy.auditReveals)
          .map(([kind]) => kind),
        actor: args.actor,
      });
    },
    /** Verifies a presented value against the kind's lookup policy and required scopes. */
    verify: <N extends Allowed<K, "hashed" | "both">>(
      ctx: MutationContext,
      args: { kind: N; value: string } & VerifyFor<K[N]>,
    ) => {
      if (requireKind(this.options, args.kind).storage === "encrypted")
        throw vaultError("VAULT_NOT_VERIFIABLE");
      return ctx.runMutation(this.component.credentials.verify, {
        kind: args.kind,
        value: args.value,
        owner: args.owner,
        requiredScopes: args.requiredScopes,
      });
    },
    /** Replaces a credential value while preserving its creation policy and use count. */
    replace: (ctx: MutationContext, args: { ref: VaultReference<KindName<K>> } & ReplaceOptions) =>
      ctx.runMutation(this.component.credentials.replace, {
        ref: validateReference(this.options, args.ref),
        value: args.value,
        graceMs: args.graceMs,
        ttlMs: args.ttlMs,
        expiresAt: args.expiresAt,
        actor: args.actor,
      }),
    /** Revokes a credential and deletes its current and previous values. */
    revoke: (ctx: MutationContext, args: { ref: VaultReference<KindName<K>>; actor?: string }) =>
      ctx.runMutation(this.component.credentials.revoke, {
        ref: validateReference(this.options, args.ref),
        actor: args.actor,
      }),
    /** Reads stored credential metadata and its current disclosure hint. */
    get: (ctx: QueryContext, args: { ref: VaultReference<KindName<K>> }) =>
      ctx.runQuery(this.component.credentials.get, {
        ref: validateReference(this.options, args.ref),
      }),
    /** Lists stored credential metadata for an owner with an optional kind filter. */
    list: (
      ctx: QueryContext,
      args: { owner: string; kind?: KindName<K>; paginationOpts: PaginationOptions },
    ) => {
      if (args.kind !== undefined) requireKind(this.options, args.kind);
      return ctx.runQuery(this.component.credentials.list, {
        owner: args.owner,
        kind: args.kind,
        paginationOpts: {
          numItems: args.paginationOpts.numItems,
          cursor: args.paginationOpts.cursor,
          endCursor: args.paginationOpts.endCursor,
        },
      });
    },
  };
  /** Reports and rotates the deployed encryption key versions. */
  readonly keys = {
    /** Reads configured master-key versions and the versions referenced by stored values. */
    getStatus: (ctx: QueryContext) => ctx.runQuery(this.component.keys.getStatus, {}),
    /** Starts batched rewrapping and rehashing with the active master-key version. */
    rotate: (ctx: MutationContext) => ctx.runMutation(this.component.keys.rotate, {}),
  };
  /** Lists the audit events recorded for credentials. */
  readonly events = {
    /** Lists stored audit events for a credential or an owner. */
    list: (
      ctx: QueryContext,
      args: {
        ref: { credentialId: string } | { owner: string };
        paginationOpts: PaginationOptions;
      },
    ) =>
      ctx.runQuery(this.component.events.list, {
        ref:
          "credentialId" in args.ref
            ? { credentialId: args.ref.credentialId }
            : { owner: args.ref.owner },
        paginationOpts: {
          numItems: args.paginationOpts.numItems,
          cursor: args.paginationOpts.cursor,
          endCursor: args.paginationOpts.endCursor,
        },
      }),
  };
}
