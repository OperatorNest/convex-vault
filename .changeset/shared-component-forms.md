---
"@operatornest/convex-vault": minor
---

Make `Vault.component` and `Vault.options` private and the `credentials`, `keys` and `events` groups readonly.
Raise the `convex-helpers` peer range to `^0.1.128`.
Reject a page cursor longer than 4096 characters, not well-formed, or not a JSON array of at most 16 primitive values with `VAULT_INVALID_ARGUMENT`, and stop each page read at 1 MiB.
Reject error data with unknown keys or malformed `retryable`, `providerStatus` or `providerCode` in `isVaultError`; `VaultErrorData` declares those three optional fields.
Forward only `numItems`, `cursor` and `endCursor` from client `paginationOpts`.
Reject kind configuration with an empty kind name, a kind name longer than 128 characters or more than 100 `auditReveals: true` kinds in the `Vault` constructor with `VAULT_INVALID_ARGUMENT`, instead of failing every reveal.
Run cleanup without `VAULT_KEYS`; a missing or malformed keyring no longer stops value, credential and event deletion.
Read the current value row in `credentials.get` and `credentials.list` only for credentials that store a hint.
Replace the `lifecycleFields` export with `lifecycleValidator`; spread `lifecycleValidator.fields` into function arguments.
Document that `verify` returns `expired` or `exhausted` until cleanup deletes the credential's values, then `not_found`.
