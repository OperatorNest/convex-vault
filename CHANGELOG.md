# @operatornest/convex-vault

## 0.1.0

### Minor Changes

- First release: encrypted and hashed credential storage as a Convex component.

  - Store customer provider keys that the app reads back (`storage: "encrypted"`) and issue API keys that the app only verifies (`storage: "hashed"`), or both (`storage: "both"`), declared per credential kind in the `Vault` constructor; the constructor rejects an invalid kind policy with `VAULT_INVALID_ARGUMENT`.
  - Each credential has an owner, an optional expiry and use limit, replacement grace, revocation and audit events.
  - The client groups methods into `credentials`, `keys` and `events`, called with `ctx` and, when the method takes arguments, one arguments object.
  - Values are encrypted or hashed with keys derived from the versioned `VAULT_KEYS` keyring through WebCrypto; `keys.rotate` rewraps values in bounded batches, and `generate-key` prints a new master key.
  - Lists return Convex pages of 1 to 100 items, read at most 1 MiB per page and reject malformed cursors with `VAULT_INVALID_ARGUMENT`.
  - A cleanup cron every 6 hours deletes expired values, credentials and events without needing `VAULT_KEYS`.
  - Errors carry fixed codes and messages, checked by `isVaultError`.
  - Requires Convex 1.46 or newer, the `convex-helpers` peer at `^0.1.128`, and Node.js 24 or newer for the CLI and tests.
