import type { FunctionArgs, FunctionReference, PaginationOptions } from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";
import { vaultError } from "../shared/errors.js";
import type { Storage, Lookup, Metadata } from "../shared/validators.js";
export { isVaultError, VAULT_ERROR_CODES } from "../shared/errors.js";
export type { VaultErrorCode, VaultErrorData } from "../shared/errors.js";
export { generateMasterKey } from "../shared/keyring.js";
export * from "../shared/validators.js";

export type KindOptions = {
  storage: Storage;
  generate?: { prefix?: string; bytes?: number };
  lookup?: Lookup;
  hint?: boolean;
  ttlMs?: number;
  maxUses?: number;
  auditReveals?: boolean;
};
export type VaultOptions<K extends Record<string, KindOptions>> = { kinds: K };
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
export type ReplaceOptions = {
  value?: string;
  graceMs?: number;
  ttlMs?: number;
  expiresAt?: number;
  actor?: string;
};
export type RevealOptions = { includePrevious?: boolean; actor?: string };
export type VerifyOptions = { owner?: string; requiredScopes?: string[] };

type KindName<K> = Extract<keyof K, string>;
type Allowed<K, S extends Storage> = {
  [P in KindName<K>]: K[P] extends { storage: S } ? P : never;
}[KindName<K>];
export type VaultReference<K extends string = string> =
  | { entryId: string; kind?: K }
  | { owner: string; kind: K; name: string };
type CreateFor<C> = CreateOptions &
  (C extends { generate: object } ? { value?: never } : { value: string });
type VerifyFor<C> = C extends { generate: object } | { lookup: "global" }
  ? [options?: VerifyOptions]
  : [options: VerifyOptions & { owner: string }];
type MutationRunner = {
  runMutation: <F extends FunctionReference<"mutation", "public" | "internal">>(
    fn: F,
    args: FunctionArgs<F>,
  ) => Promise<F["_returnType"]>;
};
type QueryRunner = {
  runQuery: <F extends FunctionReference<"query", "public" | "internal">>(
    fn: F,
    args: FunctionArgs<F>,
  ) => Promise<F["_returnType"]>;
};

/** Calls the vault component from app server functions. The app authenticates and authorizes every call before it invokes a method. */
export class Vault<const K extends Record<string, KindOptions>> {
  constructor(
    public readonly component: ComponentApi,
    public readonly options: VaultOptions<K>,
  ) {}

  private kind(name: KindName<K>): KindOptions {
    const options = this.options.kinds[name];
    if (!options) throw vaultError("VAULT_INVALID_ARGUMENT");
    return options;
  }
  private ref(ref: VaultReference<KindName<K>>) {
    if (ref.kind !== undefined) this.kind(ref.kind);
    return ref;
  }
  create<N extends KindName<K>>(ctx: MutationRunner, kind: N, options: CreateFor<K[N]>) {
    const policy = this.kind(kind);
    return ctx.runMutation(this.component.vault.create, {
      owner: options.owner,
      kind,
      value: options.value,
      name: options.name,
      label: options.label,
      scopes: options.scopes,
      metadata: options.metadata,
      expiresAt: options.expiresAt,
      actor: options.actor,
      storage: policy.storage,
      origin: policy.generate ? "generated" : "supplied",
      lookup: policy.generate ? "global" : (policy.lookup ?? "owner"),
      prefix: policy.generate?.prefix,
      bytes: policy.generate?.bytes,
      hint: policy.hint,
      auditReveals: policy.auditReveals,
      ttlMs: options.expiresAt === undefined ? (options.ttlMs ?? policy.ttlMs) : options.ttlMs,
      maxUses: options.maxUses ?? policy.maxUses,
    });
  }
  reveal(
    ctx: MutationRunner,
    ref: VaultReference<Allowed<K, "encrypted" | "both">>,
    options: RevealOptions = {},
  ) {
    if (ref.kind !== undefined && this.kind(ref.kind).storage === "hashed")
      throw vaultError("VAULT_NOT_REVEALABLE");
    return ctx.runMutation(this.component.vault.reveal, {
      ref: this.ref(ref),
      includePrevious: options.includePrevious,
      actor: options.actor,
    });
  }
  verify<N extends Allowed<K, "hashed" | "both">>(
    ctx: MutationRunner,
    kind: N,
    value: string,
    ...options: VerifyFor<K[N]>
  ) {
    if (this.kind(kind).storage === "encrypted") throw vaultError("VAULT_NOT_VERIFIABLE");
    const [{ owner, requiredScopes } = {}] = options;
    return ctx.runMutation(this.component.vault.verify, { kind, value, owner, requiredScopes });
  }
  replace(ctx: MutationRunner, ref: VaultReference<KindName<K>>, options: ReplaceOptions = {}) {
    return ctx.runMutation(this.component.vault.replace, {
      ref: this.ref(ref),
      value: options.value,
      graceMs: options.graceMs,
      ttlMs: options.ttlMs,
      expiresAt: options.expiresAt,
      actor: options.actor,
    });
  }
  revoke(ctx: MutationRunner, ref: VaultReference<KindName<K>>, options: { actor?: string } = {}) {
    return ctx.runMutation(this.component.vault.revoke, {
      ref: this.ref(ref),
      actor: options.actor,
    });
  }
  get(ctx: QueryRunner, ref: VaultReference<KindName<K>>) {
    return ctx.runQuery(this.component.vault.get, { ref: this.ref(ref) });
  }
  list(
    ctx: QueryRunner,
    options: { owner: string; kind?: KindName<K>; paginationOpts: PaginationOptions },
  ) {
    if (options.kind !== undefined) this.kind(options.kind);
    return ctx.runQuery(this.component.vault.list, {
      owner: options.owner,
      kind: options.kind,
      paginationOpts: options.paginationOpts,
    });
  }
  listEvents(
    ctx: QueryRunner,
    ref: { entryId: string } | { owner: string },
    paginationOpts: PaginationOptions,
  ) {
    return ctx.runQuery(this.component.vault.listEvents, { ref, paginationOpts });
  }
  keyStatus(ctx: QueryRunner) {
    return ctx.runQuery(this.component.maintenance.keyStatus, {});
  }
  rotateKeys(ctx: MutationRunner) {
    return ctx.runMutation(this.component.maintenance.rotateKeys, {});
  }
}
