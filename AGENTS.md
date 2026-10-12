# Working in this repository

## Scope

The package is `@operatornest/convex-vault`, component name `vault`. It stores supplied and generated credentials as ciphertext, a keyed hash, or both. App functions authenticate and authorize; component functions trust the opaque `owner` string the app passes.

Read `README.md`, `CONTRIBUTING.md`, and the ADRs in `docs/adr/` for supported behavior and decisions before changing contracts. Generated bindings are committed so the package builds without a local backend.

| Path                          | Responsibility                                                                                                                                             |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/component/`              | Tables, immutable kind policies, transactional lifecycle, key rotation and cleanup cron.                                                                   |
| `src/client/`                 | Typed server-side `Vault` wrapper and exported types, validators, error guard and key generator.                                                           |
| `src/shared/`                 | Pure keyring, HKDF, envelope encryption, lookup hashing, generation, hints, bounds and validators. No database or generated server imports.                |
| `src/test.ts`                 | `register(t)` for consumer `convex-test` instances.                                                                                                        |
| `src/test-helpers.ts`         | Test harness, generated test keys, error assertions and scheduler drain.                                                                                   |
| `scripts/check-source.mjs`    | Test-enforced source rules: no module-scope randomness, index names that list their fields, no object spreads in client component arguments.               |
| `bin/convex-vault.js`         | CLI (`generate-key`), a wrapper over `dist/shared/cli.js`. May use Node.                                                                                   |
| `example/convex/`             | Minimal app covering all six storage and origin combinations. `example.ts` holds the authenticated public functions; `admin.ts` wraps every client method. |
| `scripts/smoke.mjs`           | Acceptance journey against a local backend (`pnpm smoke`).                                                                                                 |
| `scripts/with-local-lock.mjs` | Shared local-backend lock; never edit.                                                                                                                     |

Main flows:

- **Create.** Validate the caller's kind policy and bounded inputs, record the policy on first use, generate identity IDs within the executing mutation, probe every configured hash version for duplicates, then insert entry, current value, and audit event in one transaction.
- **Reveal and verify.** Reject revoked, exhausted or expired entries. Reveal decrypts and authenticates the value against its identity AAD; verify performs keyed lookup using the recorded kind policy, rejects a match outside a supplied `owner`, and checks required scopes. Entry ID references with `kind` resolve only that kind. Both consume uses from the same optional `maxUses` limit. Without `maxUses`, reveal writes nothing to the entry and verify writes `lastUsedAt` at most once per 60 seconds.
- **Replace.** Preserve creation-time generation and hint settings; preserve expiry unless the caller renews it. Expired active entries can be renewed only by a replace that passes `ttlMs` or `expiresAt`; without either, replace fails with `VAULT_INACTIVE`. Probe duplicates before removing any old value. Keep at most one previous value during grace; grace never extends the old value past its pre-replace expiry.
- **Revoke.** Mark revoked and delete every value in the same transaction. Revoking a revoked entry by ID returns `null` without a change.
- **Rotate keys.** Process 50 entries and at most 100 values per transaction, then self-schedule on the immutable creation cursor. Rewrap `encrypted` values, rehash `both` values, and leave `hashed` values on their original hash version. Emit one rekey event per changed entry. Each batch compares a fingerprint of every configured version and key with the fingerprint taken when the job started; any difference stops the job with `VAULT_NOT_CONFIGURED`.
- **Cleanup.** Every six hours, read exhausted and revoked entries through `by_status_and_updatedAt` and expired entries through `by_expiresAt` in batches of 50; delete their values, and delete revoked and exhausted entries 30 days after `updatedAt` and expired active entries 30 days after `expiresAt`; delete past-grace previous values in batches of 100; delete events strictly older than 90 days in batches of 100. Kind policies survive cleanup.

## Runtime and security boundaries

- Authored `src/` uses WebCrypto and Web APIs only: no Node imports, `Buffer`, `process`, or Node runtime directive. `bin/` and `scripts/` may use Node.
- Zero runtime dependencies. `convex` and `convex-helpers` are peers; the latter provides component-compatible pagination.
- All randomness executes inside functions. Never call `crypto.getRandomValues` or `crypto.randomUUID` at module scope, including static initializers.
- Master keys live only in optional component env `VAULT_KEYS`, read through generated `env`. Its format is comma-separated `<version>:<key>` pairs: unique positive safe integer versions and canonical unpadded base64url 32-byte keys; the highest version is active. Any malformed keyring fails every operation with `VAULT_NOT_CONFIGURED`.
- Every caller-reachable error comes from `vaultError` with a `VAULT_*` code and that code's fixed message. Never include caller values, key material or lookup hashes in error messages, logs or function results.
- Envelope AAD binds owner, kind, entry ID, value ID, and wrapped-key version. Entry policy and lifecycle fields are outside the authenticated payload; deployment administrators already control reveal access.
- Supplied values default to owner lookup and no hints. Supplied global lookup requires at least 32 characters. Hints on supplied values disclose a suffix and weaken protection against database leaks.
- Client methods copy each declared option into component arguments and never spread a caller object, so an undeclared field cannot override a reference; `scripts/check-source.mjs` enforces this.
- Every public function has `args` and `returns`. No `v.any()`, non-null assertions, double assertions through `unknown`, unfinished-work markers, or lint suppressions in authored source.

## Query and validator patterns

Reuse `src/shared/validators.ts` and `schema.doc` instead of duplicating shapes. Every read is indexed and bounded. Use `paginator` from `convex-helpers/server/pagination` in components; never native pagination or unbounded collection. Page requests accept 1–100 items and read at most `numItems + 1` rows, including requests with `endCursor`; malformed cursors fail with `VAULT_INVALID_ARGUMENT`. Queries never read the wall clock. Index names list every field in order, joined by `_and_` (`by_owner_and_at`); `scripts/check-source.mjs` enforces this.

`keyStatus` uses indexed existence checks per configured version. Missing-version discovery walks up to 100 distinct versions per field and reports `missingVersionsTruncated` when more references exist. A truncated result is insufficient evidence to retire a key.

## Generated files

`src/component/_generated/` is generated by the Convex CLI and excluded from authored-source restrictions. Never hand-edit it. Regenerate against an isolated anonymous local backend with `convex codegen --component-dir <absolute component path>` from an initialized app, review, and commit its output.

## Toolchain and verification

Node 24 and pnpm 12.9.1 are pinned by mise; consumers need Node 24+. TypeScript native builds, with TypeScript 6 for tooling; `exactOptionalPropertyTypes` is off.

Run affected tests, then `pnpm check`. It checks formatting, build, lint, typecheck, knip, source invariants, and tests with coverage floors of 90% statements and 85% branches. Unit tests use generated or explicitly marked fixed test keys, fake time, and scheduler completion events. Never call live services or use production secrets in tests. Run `pnpm smoke` (local backend) before claiming deployed-runtime behavior. Publishing, pushing, deploying and registry submissions require explicit authorization.
