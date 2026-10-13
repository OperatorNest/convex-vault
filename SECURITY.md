# Security

## Reporting

Report vulnerabilities in `@operatornest/convex-vault` through the package repository’s Security tab (Report a vulnerability) or [operatornest+security@gmail.com](mailto:operatornest+security@gmail.com). Include the affected version, operation, code path, redacted reproduction and impact. Remove credentials, keys, endpoints, payloads, customer data and personal information. Keep exploit details private until maintainers coordinate disclosure.

The app authenticates and authorizes callers before invoking `Vault`. Report paths that bypass those boundaries or disclose component credentials prefixed `VAULT_`.

## Boundaries

A database export contains ciphertext, wrapped data keys, keyed hashes, and plaintext owners, kinds, names, labels, scopes, metadata, hints and actors. Each value's AES-256-GCM data key is wrapped with a key derived from the master key; AAD binds owner, kind, credential ID, value ID and wrapped-key version. Master keys are read from component env and never stored, returned or logged. A database export alone does not permit guessing a supplied hashed value whose kind stores no hint.

The app authenticates and authorizes callers before invoking `Vault`. Anyone holding `VAULT_KEYS` and a database copy, compromised app code, or a deployment administrator can read encrypted values. Anyone who can write the database can alter pointers, scopes, status, expiry and use counts or restore old rows; those fields are not authenticated. A leak of both the database and `VAULT_KEYS` permits offline guessing of low-entropy supplied values. Enabling hints on supplied kinds discloses part of the value.

Reports in scope: paths that expose master keys, plaintext beyond the specified return values, AEAD substitution or integrity failures, an owner-lookup verify that matches another owner's value, duplicate values bypassing uniqueness, and lifecycle or exact-use-limit bypasses.
