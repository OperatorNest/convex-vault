# 0002: Separate wrap and lookup keys with HKDF

## Decision

For each master-key version derive 256-bit keys with HKDF-SHA256, a 32-zero-byte salt and the master key as input key material. Use info `convex-vault/1/wrap` for AES-256-GCM wrapping and `convex-vault/1/hash` for HMAC-SHA256 lookup. The `1` identifies the format, independently of the master-key version.

## Consequences

One master key serves two independent cryptographic purposes without reusing key bytes. Lookup hashes are keyed, so database exports alone do not enable guessing supplied plaintext. Master-key compromise together with database compromise permits offline guesses of low-entropy supplied values. Changing either info string or salt is a format migration.
