The package is `@operatornest/convex-vault`, component name `vault`.

## Scope

The component stores supplied and generated credentials as ciphertext, a keyed hash, or both. App functions authenticate and authorize; component functions trust the opaque `owner` string the app passes.

Use the domain terms in [README Concepts](README.md#concepts). Read `README.md`, `CONTRIBUTING.md`, and the ADRs in `docs/adr/` for supported behavior and decisions before changing contracts. Generated bindings are committed so the package builds without a local backend.

| Path                          | Responsibility                                                                                                                                             |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/component/`              | Tables, immutable kind policies, transactional lifecycle, key rotation and cleanup cron.                                                                   |
| `src/client/`                 | Typed server-side `Vault` wrapper that validates kind configuration at construction, and exported types, validators, error guard and key generator.        |
| `src/shared/`                 | Pure configuration, keyring, HKDF, envelope encryption, lookup hashing, generation, hints, bounds and validators. No database or generated server imports. |
| `src/test.ts`                 | `register(t)` for consumer `convex-test` instances.                                                                                                        |
| `src/test-helpers.ts`         | Test harness, generated test keys, error assertions and scheduler drain.                                                                                   |
| `scripts/check-source.mjs`    | Test-enforced source rules: no module-scope randomness, index names that list their fields, no object spreads in client component arguments.               |
| `bin/convex-vault.js`         | CLI (`generate-key`), a wrapper over `dist/shared/cli.js`. May use Node.                                                                                   |
| `example/convex/`             | Minimal app covering all six storage and origin combinations. `example.ts` holds the authenticated public functions; `admin.ts` wraps every client method. |
| `scripts/smoke.mjs`           | Domain steps of the acceptance journey (`pnpm smoke`).                                                                                                     |
| `scripts/smoke-harness.mjs`   | Shared smoke runner that starts the local backend and deploys the example; never edit.                                                                     |
| `scripts/with-local-lock.mjs` | Shared local-backend lock; never edit.                                                                                                                     |

Main flows:

- **Create.** Validate the caller's kind policy and bounded inputs, record the policy on first use, obtain the credential row ID and generate value IDs within the executing mutation, probe every configured hash version for duplicates, then insert credential, current value, and audit event in one transaction.
- **Reveal and verify.** Reject revoked, exhausted or expired credentials. Reveal decrypts and authenticates the value against its identity AAD; verify performs keyed lookup using the recorded kind policy, rejects a match outside a supplied `owner`, and checks required scopes. Credential ID references with `kind` resolve only that kind. Reveal records an audit event when the credential's stored `auditReveals` is true or the client-sent `auditRevealsKinds` contains its kind; the client sends every configured kind whose current `auditReveals` is true. Both consume uses from the same optional `maxUses` limit. Without `maxUses`, reveal writes nothing to the credential and verify writes `lastUsedAt` at most once per 60 seconds.
- **Replace.** Preserve creation-time generation and hint settings; preserve expiry unless the caller renews it. Expired active credentials can be renewed only by a replace that passes `ttlMs` or `expiresAt`; without either, replace fails with `VAULT_INACTIVE`. Probe duplicates before removing any old value. Clear `valuesDeletedAt` so cleanup deletes the renewed values after the renewed expiry. Keep at most one previous value during grace; grace never extends the old value past its pre-replace expiry.
- **Revoke.** Mark revoked, set `valuesDeletedAt` and delete every value in the same transaction. Revoking a revoked credential by ID returns `null` without a change.
- **Rotate keys.** Process 50 credentials and at most 100 values per transaction, then self-schedule on the immutable creation cursor. Rewrap `encrypted` values, rehash `both` values, and leave `hashed` values on their original hash version. Emit one rekey event per changed credential. Each batch compares a fingerprint of every configured version and key with the fingerprint taken when the job started; any difference stops the job with `VAULT_NOT_CONFIGURED`.
- **Cleanup.** Every six hours, run seven phases in order, each in batches of 50 credentials or 100 rows that self-schedule: delete the values of exhausted and of expired active credentials whose `valuesDeletedAt` is unset, through `by_status_and_valuesDeletedAt_and_expiresAt`, and set `valuesDeletedAt`; delete exhausted and revoked credentials 30 days after `updatedAt` through `by_status_and_updatedAt`, and expired active credentials 30 days after `expiresAt` through `by_status_and_expiresAt`, with their remaining values; delete past-grace previous values; delete events strictly older than 90 days. A run reads no credential whose work is finished. After value deletion, verify of an expired or exhausted credential returns `not_found`. Kind policies survive cleanup.

## Runtime and security boundaries

- Authored `src/` uses WebCrypto and Web APIs only: no Node imports, `Buffer`, `process`, or Node runtime directive. `bin/` and `scripts/` may use Node.
- Zero runtime dependencies. `convex` and `convex-helpers` are peers; the latter provides component-compatible pagination.
- All randomness executes inside functions. Never call `crypto.getRandomValues` or `crypto.randomUUID` at module scope, including static initializers.
- Master keys live only in optional component env `VAULT_KEYS`, read through generated `env`. Its format is comma-separated `<version>:<key>` pairs: unique positive safe integer versions and canonical unpadded base64url 32-byte keys; the highest version is active. A missing or malformed keyring fails every operation except cleanup with `VAULT_NOT_CONFIGURED`; cleanup only deletes and reads no key.
- Every caller-reachable error comes from `vaultError` with a `VAULT_*` code and that code's fixed message. Never include caller values, key material or lookup hashes in error messages, logs or function results.
- Envelope AAD binds owner, kind, credential ID, value ID, and wrapped-key version. Credential policy and lifecycle fields are outside the authenticated payload; deployment administrators already control reveal access.
- Supplied values require explicit lookup and hint policy. Supplied global lookup requires at least 32 characters. Hints on supplied values disclose a suffix and weaken protection against database leaks.
- Client methods copy each declared option into component arguments and never spread a caller object, so an undeclared field cannot override a reference; `scripts/check-source.mjs` enforces this.
- Every public function has `args` and `returns`. No `v.any()`, non-null assertions, double assertions through `unknown`, unfinished-work markers, or lint suppressions in authored source.

## Query and validator patterns

Reuse `src/shared/validators.ts` and `schema.doc` instead of duplicating shapes. The client exports an explicit list of argument and result validators; never export a stored-row validator. Every read is indexed and bounded. Use `paginator` from `convex-helpers/server/pagination` in components; never native pagination or unbounded collection. Page requests accept 1–100 items and read at most `numItems + 1` rows, including requests with `endCursor`; malformed cursors fail with `VAULT_INVALID_ARGUMENT`. Queries never read the wall clock. Index names list every field in order, joined by `_and_` (`by_owner_and_occurredAt`); `scripts/check-source.mjs` enforces this.

`keys.getStatus` uses indexed existence checks per configured version. Missing-version discovery walks up to 100 distinct versions per field and reports `missingVersionsTruncated` when more references exist. A truncated result is insufficient evidence to retire a key.

## Generated files

`src/component/_generated/` is generated by the Convex CLI and excluded from authored-source restrictions. Never hand-edit it. Regenerate against an isolated anonymous local backend with `convex codegen --component-dir <absolute component path>` from an initialized app and inspect its output.

## Toolchain and verification

Node 24 and pnpm 12.9.1 are pinned by mise; consumers need Node 24+. TypeScript native builds, with TypeScript 6 for tooling; `exactOptionalPropertyTypes` is off because convex-helpers ships TypeScript source that fails it; recheck on every convex-helpers upgrade.

Run affected tests, then `pnpm check`. It checks formatting, build, lint, typecheck, knip, source invariants, and tests with coverage floors of 90% statements and 85% branches. Unit tests use generated or explicitly marked fixed test keys, fake time, and scheduler completion events. Never call live services or use production credentials in tests. Run `pnpm smoke` (local backend) before claiming deployed-runtime behavior. Publishing, pushing, deploying and registry submissions require explicit authorization.
