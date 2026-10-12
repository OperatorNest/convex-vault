# Convex Vault

Encrypted and hashed credential storage for Convex. One component stores customer provider keys that your app must read back and issues API keys that your app only verifies. Each credential has an owner, optional expiry and use limit, replacement grace and audit events.

## Install

```sh
pnpm add @operatornest/convex-vault convex convex-helpers
```

Requires Convex 1.46 or newer and, for the CLI and tests, Node.js 24 or newer. The component uses WebCrypto and has no runtime dependencies; `convex` and `convex-helpers` are peer dependencies.

## Setup

### 1. Generate a master key

```sh
npx @operatornest/convex-vault generate-key
# Prints 1:<canonical base64url 32-byte key>
```

`generate-key --version <n>` sets the key version; the default is 1. Store the output in the Convex environment variable `VAULT_KEYS` through the dashboard or `pnpm exec convex env set VAULT_KEYS '<version>:<key>'`. Never commit keys or pass them as function arguments.

`VAULT_KEYS` is a comma-separated keyring of `<version>:<key>` pairs, such as `2:<new-key>,1:<old-key>`. Each version is a unique positive safe integer; each key is exactly 32 bytes in canonical, unpadded base64url. The highest version encrypts and hashes new values. A missing or malformed keyring fails every operation with `VAULT_NOT_CONFIGURED`.

### 2. Install the component and pass it `VAULT_KEYS`

```ts
// convex/convex.config.ts
import { defineApp } from "convex/server";
import { v } from "convex/values";
import vault from "@operatornest/convex-vault/convex.config.js";

const app = defineApp({ env: { VAULT_KEYS: v.optional(v.string()) } });
app.use(vault, { env: { VAULT_KEYS: app.env.VAULT_KEYS } });
export default app;
```

### 3. Declare kinds in server code

```ts
import { Vault } from "@operatornest/convex-vault";
import { components } from "./_generated/api.js";

const vault = new Vault(components.vault, {
  kinds: {
    providerKey: { storage: "encrypted" },
    signingSecret: { storage: "encrypted", generate: { prefix: "sig_" } },
    sharedToken: { storage: "hashed" },
    apiKey: { storage: "hashed", generate: { prefix: "sk_" } },
    importedKey: { storage: "both" },
    dashboardKey: { storage: "both", generate: { prefix: "dash_" } },
  },
});
```

| Storage     | Supplied value                                    | Generated value                                          |
| ----------- | ------------------------------------------------- | -------------------------------------------------------- |
| `encrypted` | Customer provider keys and OAuth tokens: `reveal` | Webhook signing secrets: `reveal`                        |
| `hashed`    | Owner-chosen shared tokens: `verify`              | API keys, invites, magic-link and reset tokens: `verify` |
| `both`      | Imported keys: `reveal` and `verify`              | Dashboard keys: `reveal` and `verify`                    |

A kind with `generate` creates its own values and always uses global lookup. A kind without `generate` stores values your app supplies and defaults to owner lookup; set `lookup: "global"` for imported bearer tokens, which then need at least 32 characters. The component records a kind's storage, origin and lookup on its first create and rejects any later change with `VAULT_KIND_CONFLICT`; a new policy needs a new kind name.

### 4. Authorize in the app

The component trusts the `owner` string your server passes and has no access to `ctx.auth`. A public function derives `owner` from `ctx.auth`; a function that acts on another owner's entries must be internal and authorized by your app. Never pass an owner or entry ID received from a browser without checking that the caller owns it.

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
    return vault.create(ctx, "providerKey", { owner, name: "primary", value });
  },
});
```

A named reference `{ owner, kind, name }` resolves only within the given owner, so a public function that passes the authenticated owner cannot read, replace, revoke or consume another owner's entry. Global `verify` finds an entry by value alone and returns its owner; call it only where presenting the value is the authorization, as with API keys. [example/convex/example.ts](https://github.com/OperatorNest/convex-vault/blob/main/example/convex/example.ts) shows authenticated public functions; [example/convex/admin.ts](https://github.com/OperatorNest/convex-vault/blob/main/example/convex/admin.ts) shows internal functions.

## Examples for all six combinations

Each snippet runs in a server function that has already authorized `owner`. `ctx` must provide `runMutation` and `runQuery`.

```ts
// Supplied, encrypted: create never returns a supplied value.
await vault.create(ctx, "providerKey", { owner, name: "primary", value: providerKey });
const { value: savedProviderKey } = await vault.reveal(ctx, {
  owner,
  kind: "providerKey",
  name: "primary",
});

// Generated, encrypted: create returns the value; reveal returns it again for signing.
const signing = await vault.create(ctx, "signingSecret", { owner });
const signingValue = await vault.reveal(ctx, { entryId: signing.entryId, kind: "signingSecret" });

// Supplied, hashed: verify requires owner.
await vault.create(ctx, "sharedToken", { owner, value: sharedToken });
const shared = await vault.verify(ctx, "sharedToken", presented, { owner });

// Generated, hashed: create returns the value once; nothing can reveal it later.
const issued = await vault.create(ctx, "apiKey", { owner, scopes: ["read"] });
if (issued.value === undefined) throw new Error("Expected a generated value");
const verified = await vault.verify(ctx, "apiKey", issued.value, { requiredScopes: ["read"] });

// Supplied, both: verify requires owner; reveal returns the value.
const imported = await vault.create(ctx, "importedKey", { owner, value: importedToken });
await vault.verify(ctx, "importedKey", importedToken, { owner });
await vault.reveal(ctx, { entryId: imported.entryId, kind: "importedKey" });

// Generated, both: verify by value alone; reveal returns the value for display.
const dashboard = await vault.create(ctx, "dashboardKey", { owner });
if (dashboard.value === undefined) throw new Error("Expected a generated value");
await vault.verify(ctx, "dashboardKey", dashboard.value);
await vault.reveal(ctx, { entryId: dashboard.entryId, kind: "dashboardKey" });
```

`value` is optional in the create and replace result types because only generated kinds return it; check it before use. Results of `get`, `list` and `listEvents` never contain values, ciphertext, wrapped keys or lookup hashes.

## Lifecycle

Every kind accepts `name`, `label`, `scopes`, `metadata`, `ttlMs` or `expiresAt`, and `maxUses`. A `name` is unique per owner and kind. Revoking or exhausting an entry releases its name; expiry does not. A released entry's ID still resolves for `get` and `listEvents` until cleanup deletes the entry. Labels, names, scopes, metadata and actors are stored as plaintext; never put credential material in them.

```ts
const invite = await vault.create(ctx, "apiKey", {
  owner,
  ttlMs: 24 * 60 * 60 * 1000,
  maxUses: 1,
  scopes: ["accept-invite"],
  metadata: { team: "support" },
});

const ref = { owner, kind: "providerKey" as const, name: "primary" };
await vault.replace(ctx, ref, {
  value: refreshedProviderKey,
  ttlMs: 60 * 60 * 1000,
  graceMs: 30_000,
});
const secrets = await vault.reveal(ctx, ref, { includePrevious: true });
// secrets.previous, { value, validUntil }, exists only during grace.
await vault.revoke(ctx, ref);
```

- **Expiry.** `ttlMs` is a positive integer of milliseconds; `expiresAt` is a future timestamp in milliseconds. Pass at most one. A kind's `ttlMs` and `maxUses` defaults apply only on create. Replace keeps the current expiry unless it receives `ttlMs` or `expiresAt`, which also renews an expired active entry. Replacing an expired entry without either fails with `VAULT_INACTIVE`.
- **Use limit.** `maxUses` is a positive integer. Each successful reveal and each successful verify consumes one use; a failed verify or a missing scope consumes none. The entry becomes exhausted when its last use is consumed. Of concurrent operations on a single-use entry, exactly one succeeds.
- **Replace.** Replace keeps the entry's use count and the generation and hint settings it had at create. `graceMs` is a nonnegative integer of milliseconds, default 0. During grace, verify still accepts the old value and reveal with `includePrevious` returns it. At most one previous value exists; the next replace deletes it. Grace ends no later than the old value's expiry, so replacing an expired entry keeps no previous value.
- **Revoke.** Revoke deletes the current and previous values in one transaction and records one `revoked` event. Revoking again by entry ID returns `null` without a change; by name it fails with `VAULT_NOT_FOUND` because a revoked name no longer resolves.
- **Hints.** Generated kinds store a hint by default: the prefix and the last four characters. Supplied kinds store no hint by default. With `hint: true`, a supplied value of at least 16 Unicode code points stores `…` and its last four code points in plaintext; a shorter value stores no hint.
- **Audit.** Reveal records a `revealed` event unless the kind sets `auditReveals: false`. Create, replace, revoke, exhaustion and rekeying always record events. `create`, `reveal`, `replace` and `revoke` accept an optional `actor` string, recorded on their events; your app must authorize it. Events from `verify` and rotation have no actor.

Reveal without a use limit writes nothing to the entry. Verify without a use limit writes `lastUsedAt` at most once per 60 seconds per entry. With a use limit, every successful reveal and verify writes the entry, so concurrent operations on one entry serialize through Convex optimistic concurrency control.

## API reference

`new Vault(components.vault, { kinds })`. Every method takes `ctx` first.

| Method                                                                 | Context  | Result                                                                                                                       |
| ---------------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `create(ctx, kind, { owner, value?, ...options })`                     | mutation | `{ entryId, value?, hint? }`; `value` only for generated kinds                                                               |
| `reveal(ctx, ref, { includePrevious?, actor? }?)`                      | mutation | `{ value, previous?: { value, validUntil } }`; `encrypted` and `both` kinds only                                             |
| `verify(ctx, kind, value, { owner?, requiredScopes? }?)`               | mutation | `{ ok: true, entryId, owner, kind, scopes, metadata, usesLeft? }` or `{ ok: false, reason }`; `hashed` and `both` kinds only |
| `replace(ctx, ref, { value?, graceMs?, ttlMs?, expiresAt?, actor? }?)` | mutation | `{ value?, hint? }`                                                                                                          |
| `revoke(ctx, ref, { actor? }?)`                                        | mutation | `null`                                                                                                                       |
| `get(ctx, ref)`                                                        | query    | Entry metadata and the current hint, if any                                                                                  |
| `list(ctx, { owner, kind?, paginationOpts })`                          | query    | Page of entry metadata                                                                                                       |
| `listEvents(ctx, { entryId } \| { owner }, paginationOpts)`            | query    | Page of audit events                                                                                                         |
| `keyStatus(ctx)`                                                       | query    | Active and configured versions, whether any value references each version, and referenced versions missing from `VAULT_KEYS` |
| `rotateKeys(ctx)`                                                      | mutation | `null`; schedules a batched rotation                                                                                         |

`ref` is `{ entryId, kind? }` or `{ owner, kind, name }`. TypeScript infers kind names from the `kinds` option and rejects `reveal` on `hashed` kinds and `verify` on `encrypted` kinds; the component enforces both at runtime. An entry ID reference with `kind` resolves only an entry of that kind and otherwise fails with `VAULT_NOT_FOUND`; it never checks the owner. When `verify` receives `owner`, a matching value of another owner returns `not_found`, for global kinds too. Failed verification returns one reason: `not_found`, `expired`, `exhausted` or `missing_scope`. A revoked entry returns `not_found` because revoke deletes its values.

Pagination takes `{ numItems, cursor }` with `numItems` from 1 to 100 and `cursor` `null` for the first page. It returns `page`, `isDone` and `continueCursor`; pass `continueCursor` as the next `cursor` until `isDone` is true. A request that also passes `endCursor` returns the rows up to that cursor but reads at most `numItems + 1` rows; when the range holds more, it returns `pageStatus: "SplitRequired"` and `isDone: false`. A malformed cursor fails with `VAULT_INVALID_ARGUMENT`.

The package also exports option and result types, validators (including `entryResultValidator`, `createResultValidator`, `revealResultValidator` and `verifyResultValidator`), `isVaultError`, `VAULT_ERROR_CODES`, and `generateMasterKey()`, which returns a new base64url key without a version, for setup and tests.

## Key rotation runbook

1. Generate a key with the next version: `npx @operatornest/convex-vault generate-key --version 2`.
2. Add it to `VAULT_KEYS` and keep every old key: `2:<new-key>,1:<old-key>`. New writes use version 2 immediately.
3. Call `vault.rotateKeys(ctx)` from an authorized internal mutation. Each transaction processes 50 entries and at most 100 values, then schedules the next. Adding, removing or changing any version or key in `VAULT_KEYS` before the job finishes stops it with `VAULT_NOT_CONFIGURED`.
4. Poll `vault.keyStatus(ctx)`; each configured version reports `encrypted` and `hashed` booleans. Rotation rewraps `encrypted` values and rehashes `both` values. **`hashed` values keep their original hash version** because the component cannot recover their plaintext; replace or revoke them, or let them expire and be cleaned up, before you remove that key.
5. Remove an old key only when both of its booleans are false, `missingVersions` is empty and `missingVersionsTruncated` is false. A truncated result does not prove that removing a key is safe. Restoring a backup requires every key its values reference, including removed keys.

Removing a referenced key makes its values unreadable; no fallback key exists. If a job fails, restore every referenced key and run it again without changing `VAULT_KEYS`; it skips values already rotated. `keyStatus` reports whether references exist, not how many, using bounded indexed reads.

## Threat model

Protects against:

- a leaked database export or backup: it contains no plaintext, no keys and no unkeyed hashes;
- moving an encrypted payload to another value, entry, kind or owner: authenticated encryption binds each payload to its identity;
- recovering a supplied hashed value from the database alone, when its kind stores no hint.

Does not protect against:

- a leaked `VAULT_KEYS`; a leak of both the database and `VAULT_KEYS` permits offline guessing of low-entropy supplied values;
- compromised app code or deployment admin access, either of which can call `reveal`;
- anyone who can write component documents, through snapshot import or an admin key, who can change pointers, scopes, status, expiry and use counts, or restore old rows;
- access to Convex's internal execution state.

Each encrypted write uses a fresh AES-256-GCM data key and fresh IVs. HKDF-SHA256 derives separate wrapping and HMAC lookup keys from each master key. Authenticated data binds owner, kind, entry ID and value ID; each wrapped data key also binds its master-key version. Lifecycle and authorization fields are not authenticated. [docs/adr/](https://github.com/OperatorNest/convex-vault/tree/main/docs/adr) records the format decisions.

## Limits and retention

| Input                | Limit                                                                    |
| -------------------- | ------------------------------------------------------------------------ |
| Owner                | 256 characters                                                           |
| Kind and name        | 128 characters each                                                      |
| Label                | 256 characters                                                           |
| Supplied value       | 1 byte to 16 KiB of UTF-8; global lookup also requires 32 characters     |
| Scopes               | 32 scopes of up to 64 characters each                                    |
| Metadata             | 32 keys and 4 KiB as JSON; values are strings, numbers, booleans or null |
| Generated randomness | 16 to 64 bytes; default 32                                               |
| Generated prefix     | 0 to 32 characters from `A-Za-z0-9_-`                                    |
| Page size            | 1 to 100                                                                 |

Create and replace reject a value whose hash matches any stored current or previous value, under every configured hash version, including expired values that cleanup has not yet deleted. With owner lookup, two owners can store the same supplied value.

Cleanup runs every six hours in bounded batches. It deletes the values of revoked, exhausted and expired entries. It deletes revoked and exhausted entries 30 days after `updatedAt`, and expired entries 30 days after `expiresAt`, so an expired entry stays renewable for 30 days. It deletes previous values when grace ends and events older than 90 days. It never deletes kind policies. Operations enforce expiry and grace whether or not cleanup has run.

## Errors

Every error a caller can receive from the component is a `ConvexError<{ code, message }>`. Each code has one fixed message, which states the cause below and never contains caller values, keys or hashes.

```ts
import { isVaultError } from "@operatornest/convex-vault";

try {
  await vault.reveal(ctx, ref);
} catch (error) {
  if (isVaultError(error) && error.data.code === "VAULT_INACTIVE") {
    // Ask the owner to replace or create the credential.
  }
  throw error;
}
```

| Code                     | Cause                                                                                                   |
| ------------------------ | ------------------------------------------------------------------------------------------------------- |
| `VAULT_NOT_CONFIGURED`   | `VAULT_KEYS` is missing or malformed, lacks a required version, or changed during rotation              |
| `VAULT_INVALID_ARGUMENT` | An argument is invalid, missing or out of bounds                                                        |
| `VAULT_NOT_FOUND`        | The entry, name or required current value does not exist                                                |
| `VAULT_NOT_REVEALABLE`   | The entry's kind stores only a hash                                                                     |
| `VAULT_NOT_VERIFIABLE`   | The kind stores only ciphertext                                                                         |
| `VAULT_DUPLICATE_VALUE`  | A stored current or previous value has the same hash                                                    |
| `VAULT_DUPLICATE_NAME`   | The owner already has an entry of this kind with this name                                              |
| `VAULT_KIND_CONFLICT`    | Storage, origin or lookup differs from the kind's recorded policy                                       |
| `VAULT_INACTIVE`         | The entry is revoked or exhausted; reveal, and replace without new expiry, also reject an expired entry |
| `VAULT_DECRYPT_FAILED`   | The payload or wrapped key failed authentication                                                        |

## Testing and development

```ts
import { register } from "@operatornest/convex-vault/test";
import { convexTest } from "convex-test";

const t = convexTest(schema, modules);
register(t);
```

Use keys from `generateMasterKey()`, fake timers for expiry and grace, and `await t.finishAllScheduledFunctions(vi.runAllTimers)` to complete scheduled jobs. Never use production keys.

`pnpm smoke` creates a disposable anonymous local Convex backend and checks all six combinations, rejection of tampered encrypted payloads, rotation of 2,000 `encrypted` and 200 `both` entries, concurrent single-use operations, and the absence of secret material in component snapshots. It requires the system `unzip` command and never contacts a cloud deployment; it has not run against Convex Cloud.

See [CONTRIBUTING.md](https://github.com/OperatorNest/convex-vault/blob/main/CONTRIBUTING.md), [AGENTS.md](https://github.com/OperatorNest/convex-vault/blob/main/AGENTS.md) and [SECURITY.md](https://github.com/OperatorNest/convex-vault/blob/main/SECURITY.md).

Maintained by OperatorNest · Ravalika Korthiwada ([@ravalikamaker](https://github.com/ravalikamaker))

## License

MIT. See [LICENSE](LICENSE).
