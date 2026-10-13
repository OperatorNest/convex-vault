# @operatornest/convex-vault

Encrypted and hashed credential storage for Convex. One component stores customer provider keys that your app must read back and issues API keys that your app only verifies. Each credential has an owner, optional expiry and use limit, replacement grace and audit events.

## Install

```sh
pnpm add @operatornest/convex-vault convex convex-helpers
```

Requires Convex 1.46 or newer and, for the CLI and tests, Node.js 24 or newer. The component uses WebCrypto and has no runtime dependencies; `convex` and `convex-helpers` are peer dependencies.

## Configure

| Variable     | Required                                                                        | Default | Valid values                                                                                                                     |
| ------------ | ------------------------------------------------------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `VAULT_KEYS` | Yes for every operation except cleanup; optional in the component env validator | None    | Comma-separated `<version>:<key>` pairs with unique positive safe-integer versions and canonical unpadded base64url 32-byte keys |

The highest version is active for new values and rotation. Keep every version referenced by stored values; missing or malformed configuration raises `VAULT_NOT_CONFIGURED`, as does an operation that needs an unavailable key. Bind the app environment variable to the component env as shown below. The vault has no provider and no test mode.

## Quick start

### Generate a master key

```sh
npx @operatornest/convex-vault generate-key
# Prints 1:<canonical base64url 32-byte key>
```

`generate-key --version <n>` sets the key version; the default is 1. Store the output in the Convex environment variable `VAULT_KEYS` through the dashboard or `pnpm exec convex env set VAULT_KEYS '<version>:<key>'`. Never commit keys or pass them as function arguments.

`VAULT_KEYS` is a comma-separated keyring of `<version>:<key>` pairs, such as `2:<new-key>,1:<old-key>`. Each version is a unique positive safe integer; each key is exactly 32 bytes in canonical, unpadded base64url. The highest version encrypts and hashes new values. A missing or malformed keyring fails every operation except cleanup with `VAULT_NOT_CONFIGURED`; cleanup deletes without keys.

### Install the component

```ts
// convex/convex.config.ts
import { defineApp } from "convex/server";
import { v } from "convex/values";
import vault from "@operatornest/convex-vault/convex.config.js";

const app = defineApp({ env: { VAULT_KEYS: v.optional(v.string()) } });
app.use(vault, { env: { VAULT_KEYS: app.env.VAULT_KEYS } });
export default app;
```

### Declare credential kinds

```ts
import { Vault } from "@operatornest/convex-vault";
import { components } from "./_generated/api.js";

const vault = new Vault(components.vault, {
  kinds: {
    providerKey: { storage: "encrypted", lookup: "owner", hint: false, auditReveals: true },
    signingKey: {
      storage: "encrypted",
      generate: { prefix: "sig_", bytes: 32 },
      hint: true,
      auditReveals: true,
    },
    sharedToken: { storage: "hashed", lookup: "owner", hint: false, auditReveals: true },
    apiKey: {
      storage: "hashed",
      generate: { prefix: "sk_", bytes: 32 },
      hint: true,
      auditReveals: true,
    },
    importedKey: { storage: "both", lookup: "owner", hint: false, auditReveals: true },
    dashboardKey: {
      storage: "both",
      generate: { prefix: "dash_", bytes: 32 },
      hint: true,
      auditReveals: true,
    },
  },
});
```

| Storage     | Supplied value                                    | Generated value                                          |
| ----------- | ------------------------------------------------- | -------------------------------------------------------- |
| `encrypted` | Customer provider keys and OAuth tokens: `reveal` | Webhook signing credentials: `reveal`                    |
| `hashed`    | Owner-chosen shared tokens: `verify`              | API keys, invites, magic-link and reset tokens: `verify` |
| `both`      | Imported keys: `reveal` and `verify`              | Dashboard keys: `reveal` and `verify`                    |

A kind with `generate` creates its own values and always uses global lookup. A kind without `generate` stores values your app supplies and requires explicit lookup; use `lookup: "global"` for imported bearer tokens, which then need at least 32 characters. The component records a kind's storage, origin and lookup on its first create and rejects any later change with `VAULT_KIND_CONFLICT`; a new policy needs a new kind name.

### Authorize in the app

The component trusts the `owner` string your server passes and has no access to `ctx.auth`. A public function derives `owner` from `ctx.auth`; a function that acts on another owner's credentials must be internal and authorized by your app. Never pass an owner or credential ID received from a browser without checking that the caller owns it.

```ts
import { ConvexError, v } from "convex/values";
import { createResultValidator } from "@operatornest/convex-vault";
import { mutation, type QueryCtx } from "./_generated/server.js";

async function requireOwner(ctx: QueryCtx): Promise<string> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new ConvexError("Not signed in");
  return identity.tokenIdentifier;
}

export const saveProviderKey = mutation({
  args: { value: v.string() },
  returns: createResultValidator,
  handler: async (ctx, { value }) => {
    const owner = await requireOwner(ctx);
    return vault.credentials.create(ctx, {
      owner,
      name: "primary",
      value,
      kind: "providerKey",
    });
  },
});
```

A named reference `{ owner, kind, name }` resolves only within the given owner, so a public function that passes the authenticated owner cannot read, replace, revoke or consume another owner's credential. Global `verify` finds a credential by value alone and returns its owner; call it only where presenting the value is the authorization, as with API keys. [example/convex/example.ts](https://github.com/OperatorNest/convex-vault/blob/main/example/convex/example.ts) shows authenticated public functions; [example/convex/admin.ts](https://github.com/OperatorNest/convex-vault/blob/main/example/convex/admin.ts) shows internal functions.

## Concepts

| Term                                                                                 | Meaning                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credential; `credentials`                                                            | A stored credential with ownership, immutable kind policy and lifecycle; the aggregate creates, reveals, verifies, replaces, revokes, gets and lists credentials.                                                             |
| Master key; `keys`                                                                   | A versioned 32-byte key used to derive independent wrapping and lookup keys; the aggregate gets key status and starts rotation.                                                                                               |
| Keyring; `VAULT_KEYS`                                                                | The configured set of master-key versions; its highest version encrypts and hashes new values.                                                                                                                                |
| Audit event; `events`                                                                | A stored record of a credential operation; the aggregate lists events by credential or owner.                                                                                                                                 |
| `credentialId`                                                                       | The credential's Convex row ID, returned on create and used in references and events.                                                                                                                                         |
| `owner`                                                                              | An opaque user, team or organization identifier supplied and authorized by the app.                                                                                                                                           |
| `actor`                                                                              | An optional app-authorized identifier of who performed an operation, recorded only on audit events.                                                                                                                           |
| Kind                                                                                 | An app-defined credential category whose storage, origin and lookup policy is recorded on first creation.                                                                                                                     |
| `storage`; `encrypted`, `hashed`, `both`                                             | Ciphertext supports reveal; a keyed hash supports verify; both stores ciphertext and a keyed hash.                                                                                                                            |
| `origin`; `generated`, `supplied`                                                    | Generated values are produced inside a mutation and returned on create or replace; supplied values come from the app and are never returned on create or replace.                                                             |
| `lookup`; `owner`, `global`                                                          | Owner lookup hashes the owner with the value; global lookup resolves ownership from the value and requires at least 32 characters for supplied values.                                                                        |
| `generate`, `prefix`, `bytes`                                                        | Generation settings: an optional prefix and an explicit number of random bytes from 16 to 64; generated kinds always use global lookup.                                                                                       |
| Reference; `ref`                                                                     | A credential row ID with an optional kind constraint, or an owner, kind and name.                                                                                                                                             |
| `name`, `label`                                                                      | A name is unique within owner and kind while active; a label is descriptive plaintext.                                                                                                                                        |
| `scopes`, `requiredScopes`                                                           | Plaintext permissions attached to a credential and permissions required by verification.                                                                                                                                      |
| `metadata`                                                                           | Caller-supplied plaintext scalar fields stored on the credential.                                                                                                                                                             |
| Hint; `hint`                                                                         | An explicitly enabled plaintext prefix and suffix that discloses part of a value; a credential result's hint contains that text.                                                                                              |
| `auditReveals`                                                                       | An explicit kind policy controlling whether reveals record audit events; the client sends its current setting with every reveal and the credential stores the setting from its creation.                                      |
| `status`; `active`, `revoked`, `exhausted`                                           | Creation enters active; revoke enters revoked and deletes values; consuming the last allowed use enters exhausted; terminal statuses release the name.                                                                        |
| Expiry; `ttlMs`, `expiresAt`                                                         | An optional positive lifetime in milliseconds or expiry timestamp; expiry leaves status active, and replacement with new expiry renews it.                                                                                    |
| `maxUses`, `useCount`, `usesLeft`                                                    | An optional shared reveal/verify use limit, consumed uses and remaining uses after successful verification.                                                                                                                   |
| `lastUsedAt`, `createdAt`, `updatedAt`                                               | Millisecond Unix timestamps for throttled verification usage, creation and lifecycle updates.                                                                                                                                 |
| `value`, `previous`                                                                  | Current credential plaintext and an optional previous plaintext with its grace deadline; supplied create and replace results omit value.                                                                                      |
| Value state; `current`, `previous`                                                   | Creation writes current; replacement may retain the old value as previous during grace; the next replacement or cleanup deletes previous.                                                                                     |
| Grace; `graceMs`, `validUntilAt`, `includePrevious`                                  | Optional retention of the old value in milliseconds, its deadline as a millisecond Unix timestamp, and a reveal request to include it.                                                                                        |
| Event `type`; `created`, `revealed`, `replaced`, `revoked`, `exhausted`, `rekeyed`   | Creation, audited reveal, replacement, revocation, final-use consumption and changed key rotation respectively append these event types.                                                                                      |
| Event `occurredAt`                                                                   | The event's millisecond Unix timestamp.                                                                                                                                                                                       |
| Verification; `ok`, `reason`                                                         | Success returns ownership, scopes and metadata; failure returns `not_found`, `expired`, `exhausted` or `missing_scope` without consuming a use; `expired` and `exhausted` become `not_found` once cleanup deletes the values. |
| `not_found`, `expired`, `missing_scope`                                              | No matching authorized value, an expired credential or grace value, or absent required scopes, respectively.                                                                                                                  |
| Key version; `activeVersion`, `versions`, `version`                                  | The highest configured version, configured version records and each record's version number.                                                                                                                                  |
| Key references; `encrypted`, `hashed`, `missingVersions`, `missingVersionsTruncated` | Whether values reference a configured wrapping or hash version, referenced unconfigured versions and whether discovery exceeded 100 distinct versions per field.                                                              |
| `paginationOpts`, `page`, `isDone`, `continueCursor`                                 | Convex page request and result fields; requests accept 1–100 rows and the page scan reads at most one extra row.                                                                                                              |
| `pageStatus`; `SplitRecommended`, `SplitRequired`                                    | Convex recommends splitting a cursor range or requires a split because the range exceeds the read bound, respectively.                                                                                                        |
| `numItems`, `cursor`, `endCursor`, `splitCursor`                                     | The requested row count, Convex continuation and optional end cursors, and an optional cursor at which to split a range.                                                                                                      |

## Examples for all six combinations

Each snippet runs in a server function that has already authorized `owner`. `ctx` must provide `runMutation` and `runQuery`.

```ts
// Supplied, encrypted: create never returns a supplied value.
await vault.credentials.create(ctx, {
  owner,
  name: "primary",
  value: providerKey,
  kind: "providerKey",
});
const { value: savedProviderKey } = await vault.credentials.reveal(ctx, {
  ref: {
    owner,
    kind: "providerKey",
    name: "primary",
  },
});

// Generated, encrypted: create returns the value; reveal returns it again for signing.
const signing = await vault.credentials.create(ctx, { owner, kind: "signingKey" });
const signingValue = await vault.credentials.reveal(ctx, {
  ref: { credentialId: signing.credentialId, kind: "signingKey" },
});

// Supplied, hashed: verify requires owner.
await vault.credentials.create(ctx, { owner, value: sharedToken, kind: "sharedToken" });
const shared = await vault.credentials.verify(ctx, {
  owner,
  kind: "sharedToken",
  value: presented,
});

// Generated, hashed: create returns the value once; nothing can reveal it later.
const issued = await vault.credentials.create(ctx, {
  owner,
  scopes: ["read"],
  kind: "apiKey",
});
if (issued.value === undefined) throw new Error("Expected a generated value");
const verified = await vault.credentials.verify(ctx, {
  requiredScopes: ["read"],
  kind: "apiKey",
  value: issued.value,
});

// Supplied, both: verify requires owner; reveal returns the value.
const imported = await vault.credentials.create(ctx, {
  owner,
  value: importedToken,
  kind: "importedKey",
});
await vault.credentials.verify(ctx, { owner, kind: "importedKey", value: importedToken });
await vault.credentials.reveal(ctx, {
  ref: { credentialId: imported.credentialId, kind: "importedKey" },
});

// Generated, both: verify by value alone; reveal returns the value for display.
const dashboard = await vault.credentials.create(ctx, { owner, kind: "dashboardKey" });
if (dashboard.value === undefined) throw new Error("Expected a generated value");
await vault.credentials.verify(ctx, { kind: "dashboardKey", value: dashboard.value });
await vault.credentials.reveal(ctx, {
  ref: { credentialId: dashboard.credentialId, kind: "dashboardKey" },
});
```

`value` is optional in the create and replace result types because only generated kinds return it; check it before use. Results of `get`, `list` and `events.list` never contain values, ciphertext, wrapped keys or lookup hashes.

## Lifecycle

Every kind accepts `name`, `label`, `scopes`, `metadata`, `ttlMs` or `expiresAt`, and `maxUses`. A `name` is unique per owner and kind. Revoking or exhausting a credential releases its name; expiry does not. A released credential's ID still resolves for `get` until cleanup deletes the credential; `events.list` returns its retained events even after credential cleanup. Labels, names, scopes, metadata and actors are stored as plaintext; never put credential material in them.

```ts
const invite = await vault.credentials.create(ctx, {
  owner,
  ttlMs: 24 * 60 * 60 * 1000,
  maxUses: 1,
  scopes: ["accept-invite"],
  metadata: { team: "support" },
  kind: "apiKey",
});

const ref = { owner, kind: "providerKey" as const, name: "primary" };
await vault.credentials.replace(ctx, {
  value: refreshedProviderKey,
  ttlMs: 60 * 60 * 1000,
  graceMs: 30_000,
  ref,
});
const revealed = await vault.credentials.reveal(ctx, { includePrevious: true, ref });
// revealed.previous, { value, validUntilAt }, exists only during grace.
await vault.credentials.revoke(ctx, { ref });
```

- **Expiry.** `ttlMs` is a positive integer of milliseconds; `expiresAt` is a future timestamp in milliseconds. Pass at most one. A kind's `ttlMs` and `maxUses` defaults apply only on create. Replace keeps the current expiry unless it receives `ttlMs` or `expiresAt`, which also renews an expired active credential. Replacing an expired credential without either fails with `VAULT_INACTIVE`.
- **Use limit.** `maxUses` is a positive integer. Each successful reveal and each successful verify consumes one use; a failed verify or a missing scope consumes none. The credential becomes exhausted when its last use is consumed. Of concurrent operations on a single-use credential, exactly one succeeds.
- **Replace.** Replace keeps the credential's use count and the generation and hint settings it had at create. `graceMs` is a nonnegative integer of milliseconds, default 0. During grace, verify still accepts the old value and reveal with `includePrevious` returns it. At most one previous value exists; the next replace deletes it. Grace ends no later than the old value's expiry, so replacing an expired credential keeps no previous value.
- **Revoke.** Revoke deletes the current and previous values in one transaction and records one `revoked` event. Revoking again by credential ID returns `null` without a change; by name it fails with `VAULT_NOT_FOUND` because a revoked name no longer resolves.
- **Hints.** When `hint: true`, generated kinds store a hint: the prefix and the last four characters. Every kind explicitly chooses `hint` and `auditReveals`. With `hint: true`, a supplied value of at least 16 Unicode code points stores `…` and its last four code points in plaintext; a shorter value stores no hint.
- **Audit.** Reveal records a `revealed` event when the client's current configuration for the credential's kind or the policy stored on the credential at creation sets `auditReveals: true`. Turning `auditReveals` on in the client audits reveals of existing credentials of that kind; turning it off does not stop auditing credentials created with it on. Create, replace, revoke, exhaustion and rekeying always record events. `create`, `reveal`, `replace` and `revoke` accept an optional `actor` string, recorded on their events; your app must authorize it. Events from `verify` and rotation have no actor.

Reveal without a use limit writes nothing to the credential. Verify without a use limit writes `lastUsedAt` at most once per 60 seconds per credential. With a use limit, every successful reveal and verify writes the credential, so concurrent operations on one credential serialize through Convex optimistic concurrency control.

## Key rotation runbook

1. Generate a key with the next version: `npx @operatornest/convex-vault generate-key --version 2`.
2. Add it to `VAULT_KEYS` and keep every old key: `2:<new-key>,1:<old-key>`. New writes use version 2 immediately.
3. Call `vault.keys.rotate(ctx)` from an authorized internal mutation. Each transaction processes 50 credentials and at most 100 values, then schedules the next. Adding, removing or changing any version or key in `VAULT_KEYS` before the job finishes stops it with `VAULT_NOT_CONFIGURED`.
4. Poll `vault.keys.getStatus(ctx)`; each configured version reports `encrypted` and `hashed` booleans. Rotation rewraps `encrypted` values and rehashes `both` values. **`hashed` values keep their original hash version** because the component cannot recover their plaintext; replace or revoke them, or let them expire and be cleaned up, before you remove that key.
5. Remove an old key only when both of its booleans are false, `missingVersions` is empty and `missingVersionsTruncated` is false. A truncated result does not prove that removing a key is safe. Restoring a backup requires every key its values reference, including removed keys.

Removing a referenced key makes its values unreadable; no fallback key exists. If a job fails, restore every referenced key and run it again without changing `VAULT_KEYS`; it skips values already rotated. `keys.getStatus` reports whether references exist, not how many, using bounded indexed reads.

## Threat model

Protects against:

- a leaked database export or backup: it contains no plaintext credential values, no master keys and no unkeyed hashes;
- moving an encrypted payload to another value, credential, kind or owner: authenticated encryption binds each payload to its identity;
- recovering a supplied hashed value from the database alone, when its kind stores no hint.

Does not protect against:

- a leaked `VAULT_KEYS`; a leak of both the database and `VAULT_KEYS` permits offline guessing of low-entropy supplied values;
- compromised app code or deployment admin access, either of which can call `reveal`;
- anyone who can write component documents, through snapshot import or an admin key, who can change pointers, scopes, status, expiry and use counts, or restore old rows;
- access to Convex's internal execution state.

Each encrypted write uses a fresh AES-256-GCM data key and fresh IVs. HKDF-SHA256 derives separate wrapping and HMAC lookup keys from each master key. Authenticated data binds owner, kind, credential ID and value ID; each wrapped data key also binds its master-key version. Lifecycle and authorization fields are not authenticated. [docs/adr/](https://github.com/OperatorNest/convex-vault/tree/main/docs/adr) records the format decisions.

## API reference

`new Vault(components.vault, { kinds })` configures credential kinds; omitting options leaves no credential kinds available. Every method takes `(ctx, args)`, or only `ctx` where Arguments is none. Groups call the same-named component modules.

| Method                | Context           | Arguments                                                                                          | Result                                                                                            |
| --------------------- | ----------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `credentials.create`  | `MutationContext` | `{ kind, owner, value?, name?, label?, scopes?, metadata?, ttlMs?, expiresAt?, maxUses?, actor? }` | `{ credentialId, value?, hint? }`; value only for generated kinds                                 |
| `credentials.reveal`  | `MutationContext` | `{ ref, includePrevious?, actor? }`                                                                | `{ value, previous?: { value, validUntilAt } }`                                                   |
| `credentials.verify`  | `MutationContext` | `{ kind, value, owner?, requiredScopes? }`                                                         | `{ ok: true, credentialId, owner, kind, scopes, metadata, usesLeft? }` or `{ ok: false, reason }` |
| `credentials.replace` | `MutationContext` | `{ ref, value?, graceMs?, ttlMs?, expiresAt?, actor? }`                                            | `{ value?, hint? }`                                                                               |
| `credentials.revoke`  | `MutationContext` | `{ ref, actor? }`                                                                                  | `null`                                                                                            |
| `credentials.get`     | `QueryContext`    | `{ ref }`                                                                                          | Stored credential metadata and current hint                                                       |
| `credentials.list`    | `QueryContext`    | `{ owner, kind?, paginationOpts }`                                                                 | Page of stored credential metadata                                                                |
| `events.list`         | `QueryContext`    | `{ ref: { credentialId } \| { owner }, paginationOpts }`                                           | Page of stored audit events                                                                       |
| `keys.getStatus`      | `QueryContext`    | none                                                                                               | Configured versions, value references and missing versions                                        |
| `keys.rotate`         | `MutationContext` | none                                                                                               | `null`; schedules batched rotation                                                                |

`ref` is `{ credentialId, kind? }` or `{ owner, kind, name }`. TypeScript infers kind names from the `kinds` option and rejects `reveal` on `hashed` kinds and `verify` on `encrypted` kinds; the component enforces both at runtime. A credential ID reference with `kind` resolves only a credential of that kind and otherwise fails with `VAULT_NOT_FOUND`; it never checks the owner. When `verify` receives `owner`, a matching value of another owner returns `not_found`, for global kinds too. Failed verification returns one reason: `not_found`, `expired`, `exhausted` or `missing_scope`. A revoked credential returns `not_found` because revoke deletes its values; an expired or exhausted credential returns `expired` or `exhausted` until cleanup deletes its values, then `not_found`.

Pagination takes `{ numItems, cursor }` with `numItems` from 1 to 100 and `cursor` `null` for the first page. It returns `page`, `isDone` and `continueCursor`; pass `continueCursor` as the next `cursor` until `isDone` is true. A request that also passes `endCursor` returns the rows up to that cursor, scans at most `numItems + 1` rows and 1 MiB and can return all of them; when the range holds more, it returns `pageStatus: "SplitRequired"` and `isDone: false`. A cursor that is longer than 4096 characters, not well-formed, or not a JSON array of at most 16 primitive values fails with `VAULT_INVALID_ARGUMENT`. The client forwards only `numItems`, `cursor` and `endCursor`. Besides the page scan, `credentials.list` reads one value row per returned credential that stores a hint.

`credentials.list` returns credentials newest first by `createdAt`; without `kind` it orders across every kind of the owner.

The package also exports option and result types, argument and result validators (including `lifecycleValidator`, whose `.fields` supply the optional `ttlMs`, `expiresAt` and `maxUses` arguments, `credentialResultValidator`, `createResultValidator`, `revealResultValidator`, `verifyResultValidator` and `keyStatusResultValidator`) but no stored-row validators, `isVaultError`, `VAULT_ERROR_CODES`, and `generateMasterKey()`, which returns a new base64url key without a version, for setup and tests.

## Errors

Every vault error is a `ConvexError<{ code, message }>` with a fixed message. `isVaultError` checks both the code and its exact message.

| Code                     | Message                                                                                              | When                                                                                                 |
| ------------------------ | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `VAULT_NOT_CONFIGURED`   | VAULT_KEYS is missing or malformed, lacks a required key version, or changed during key rotation.    | Component env is absent or malformed, a referenced key is absent, or rotation configuration changed. |
| `VAULT_INVALID_ARGUMENT` | An argument is invalid, missing or out of bounds.                                                    | An input, cursor or page size fails validation.                                                      |
| `VAULT_NOT_FOUND`        | The credential, name or required current value does not exist.                                       | A credential reference or required current value cannot be resolved.                                 |
| `VAULT_NOT_REVEALABLE`   | The credential's kind stores only a hash, so its value cannot be revealed.                           | Reveal targets a hashed kind.                                                                        |
| `VAULT_NOT_VERIFIABLE`   | The kind stores only ciphertext, so its values cannot be verified.                                   | Verify targets an encrypted kind.                                                                    |
| `VAULT_DUPLICATE_VALUE`  | A stored current or previous value has the same hash.                                                | Create or replace finds a reserved value hash.                                                       |
| `VAULT_DUPLICATE_NAME`   | The owner already has a credential of this kind with this name.                                      | Create finds a reserved name within owner and kind.                                                  |
| `VAULT_KIND_CONFLICT`    | Storage, origin or lookup differs from the kind's recorded policy.                                   | Create conflicts with recorded kind policy.                                                          |
| `VAULT_INACTIVE`         | The credential is revoked or exhausted, or expired for a reveal or for a replace without new expiry. | An operation rejects terminal status or unrenewed expiry.                                            |
| `VAULT_DECRYPT_FAILED`   | The payload or wrapped key failed authentication.                                                    | Encrypted payload or wrapped key authentication fails.                                               |

## Testing

```ts
import { register } from "@operatornest/convex-vault/test";
import { convexTest } from "convex-test";

const t = convexTest(schema, modules);
register(t);
```

Use keys from `generateMasterKey()`, fake timers for expiry and grace, and `await t.finishAllScheduledFunctions(vi.runAllTimers)` to complete scheduled jobs. Never use production keys.

## Limits and retention

| Input                   | Limit                                                                    |
| ----------------------- | ------------------------------------------------------------------------ |
| Owner                   | 1 to 256 characters                                                      |
| Kind and name           | 1 to 128 characters each                                                 |
| Label                   | 1 to 256 characters                                                      |
| Actor                   | 1 to 256 characters                                                      |
| Credential ID reference | 1 to 128 characters                                                      |
| Supplied value          | 1 byte to 16 KiB of UTF-8; global lookup also requires 32 characters     |
| Scopes                  | 32 scopes of 1 to 64 characters each                                     |
| Metadata                | 32 keys and 4 KiB as JSON; values are strings, numbers, booleans or null |
| Generated randomness    | 16 to 64 bytes; explicit in kind configuration                           |
| Generated prefix        | 0 to 32 characters from `A-Za-z0-9_-`                                    |
| Page size               | 1 to 100                                                                 |
| Cursor                  | 4096 characters; a JSON array of at most 16 primitive values             |
| Audited kinds           | 100 kinds with `auditReveals: true` per client; 128 characters each      |

Character limits count UTF-16 code units (JavaScript `string.length`); hint thresholds count Unicode code points.

For `hashed` and `both` kinds, create and replace reject a value whose hash matches any stored current or previous value, under every configured hash version, including expired values that cleanup has not yet deleted. With owner lookup, two owners can store the same supplied value.

Cleanup runs every six hours in bounded batches. Revoke deletes values immediately; cleanup deletes the values of exhausted and expired credentials once, after which verify returns `not_found` for them; a later run skips credentials whose values are gone, and renewing an expired credential makes cleanup delete its values again after the renewed expiry. It deletes revoked and exhausted credentials 30 days after `updatedAt`, and expired credentials 30 days after `expiresAt`, so an expired credential stays renewable for 30 days. It deletes previous values when grace ends and events older than 90 days. It never deletes kind policies. Operations enforce expiry and grace whether or not cleanup has run.

## Security

The app authenticates and authorizes every caller before invoking the component. Owner-scoped references enforce the supplied owner; credential ID references do not authorize ownership. Hints weaken database-leak protection, so select hint policy explicitly. Keep master keys outside arguments, documents and logs. Encrypted values are bound to their credential's document ID, so a restore must preserve document IDs, which Convex snapshot export and import do. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Development

`pnpm smoke` creates a disposable anonymous local Convex backend and checks all six combinations, rejection of tampered encrypted payloads, rotation of 2,000 `encrypted` and 200 `both` credentials, concurrent single-use operations, cleanup of exhausted, expired and renewed credentials, and the absence of plaintext credential material in component snapshots. It requires the system `unzip` command and never contacts a cloud deployment; it has not run against Convex Cloud.

See [CONTRIBUTING.md](https://github.com/OperatorNest/convex-vault/blob/main/CONTRIBUTING.md), [AGENTS.md](https://github.com/OperatorNest/convex-vault/blob/main/AGENTS.md) and [SECURITY.md](https://github.com/OperatorNest/convex-vault/blob/main/SECURITY.md).

Maintained by OperatorNest · Ravalika Korthiwada ([@ravalikamaker](https://github.com/ravalikamaker))

## License

MIT. See [LICENSE](LICENSE).
