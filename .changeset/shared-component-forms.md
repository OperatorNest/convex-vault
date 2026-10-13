---
"@operatornest/convex-vault": minor
---

Make `Vault.component` and `Vault.options` private and the `credentials`, `keys` and `events` groups readonly.
Raise the `convex-helpers` peer range to `^0.1.128`.
Reject a page cursor longer than 4096 characters, not well-formed, or not a JSON array of at most the selected index's key length in primitive values with `VAULT_INVALID_ARGUMENT`, and stop each page read at 1 MiB.
Reject error data with unknown keys or malformed `retryable`, `providerStatus` or `providerCode` in `isVaultError`; `VaultErrorData` declares those three optional fields.
Forward only `numItems`, `cursor` and `endCursor` from client `paginationOpts`.
Reject kind configuration with an empty kind name, a kind name longer than 128 characters or more than 100 `auditReveals: true` kinds in the `Vault` constructor with `VAULT_INVALID_ARGUMENT`, instead of failing every reveal.
Run cleanup without `VAULT_KEYS`; a missing or malformed keyring no longer stops value, credential and event deletion.
Read the current value row in `credentials.get` and `credentials.list` only for credentials that store a hint.
Replace the `lifecycleFields` export with `lifecycleValidator`; spread `lifecycleValidator.fields` into function arguments.
Document that `verify` returns `expired` or `exhausted` until cleanup deletes the credential's values, then `not_found`.
Reject an owner, kind, name, label, actor, scope, credential ID reference or configured kind name that contains an unpaired surrogate with `VAULT_INVALID_ARGUMENT`.
Reject a `VAULT_KEYS` value with leading or trailing whitespace or an unpaired surrogate with `VAULT_NOT_CONFIGURED`.
Change the `VAULT_INVALID_ARGUMENT` message to "An argument is missing, malformed or out of bounds."

Validate every configured kind's storage, lookup, generation, hint, audit policy and positive safe-integer lifecycle defaults in the `Vault` constructor; invalid policies now throw `VAULT_INVALID_ARGUMENT` before the first operation.
Bound both page cursors by the selected index's declared fields plus `_creationTime` and `_id`: four values for owner credential lists and event lists, five for kind-filtered credential lists; shorter arrays remain valid prefix bounds.
Define `retryable` as requiring both a transient failure and an identical call that cannot create a second provider effect; vault has no provider-originated error codes and never sets it.
