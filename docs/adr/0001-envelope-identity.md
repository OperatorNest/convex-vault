# 0001: Envelope encryption binds value identity

## Decision

Each encrypted value uses a fresh 32-byte AES-256-GCM data key and two fresh 12-byte IVs. The master-derived wrap key encrypts that data key. Ciphertext and wrapped-key bytes are stored as canonical base64url.

Value AAD is UTF-8 JSON `["convex-vault",1,"value",owner,kind,entryId,valueId]`. Key AAD is UTF-8 JSON `["convex-vault",1,"key",owner,kind,entryId,valueId,keyVersion]`. Entry and value IDs are 16 random bytes, base64url, created before insertion. JSON arrays give unambiguous boundaries; the format version distinguishes future encodings.

## Consequences

Swapping ciphertext or wrapped keys across values, entries, kinds or owners fails authentication. Rewrapping changes the wrapped-key version and its AAD without re-encrypting the payload. Entry pointers, scopes, status, expiry and use counts are not authenticated; deployment administrators can already reveal values and roll entire rows back. The documented threat model protects payload identity, not database-admin authorization changes.
