# 0001: Envelope encryption binds value identity

Each encrypted value uses a fresh 32-byte AES-256-GCM data key and two fresh 12-byte IVs. The master-derived wrap key encrypts that data key. Ciphertext and wrapped-key bytes are stored as canonical base64url.

Value AAD is UTF-8 JSON `["convex-vault",1,"value",owner,kind,credentialId,valueId]`. Key AAD is UTF-8 JSON `["convex-vault",1,"key",owner,kind,credentialId,valueId,keyVersion]`. Credential IDs are Convex row IDs; value IDs are 16 random bytes encoded as base64url inside the executing mutation. JSON arrays give unambiguous boundaries; the format version distinguishes future encodings.

Swapping ciphertext or wrapped keys across values, credentials, kinds or owners fails authentication. Rewrapping changes the wrapped-key version and its AAD without re-encrypting the payload. Credential pointers, scopes, status, expiry and use counts are not authenticated; deployment administrators can already reveal values and roll entire rows back. The documented threat model protects payload identity, not database-admin authorization changes.
