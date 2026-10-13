---
"@operatornest/convex-vault": minor
---

Make `Vault.component` and `Vault.options` private and the `credentials`, `keys` and `events` groups readonly.
Raise the `convex-helpers` peer range to `^0.1.128`.
Reject a page cursor longer than 4096 characters, not well-formed, or not a JSON array of at most 16 primitive values with `VAULT_INVALID_ARGUMENT`, and stop each page read at 1 MiB.
Reject error data with unknown keys or malformed `retryable`, `providerStatus` or `providerCode` in `isVaultError`; `VaultErrorData` declares those three optional fields.
Forward only `numItems`, `cursor` and `endCursor` from client `paginationOpts`.
