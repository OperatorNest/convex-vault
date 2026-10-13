# 0002: Separate wrap, lookup and fingerprint keys with HKDF

For each master-key version derive 256-bit keys with HKDF-SHA256, a 32-zero-byte salt and the master key as input key material. Use info `convex-vault/1/wrap` for AES-256-GCM wrapping, `convex-vault/1/hash` for HMAC-SHA256 lookup and `convex-vault/1/fingerprint` for the keyring fingerprint that a rotation job compares between batches. Derived wrap and hash keys are cached per version for one function call. The `1` identifies the format, independently of the master-key version.

One master key serves three independent cryptographic purposes without reusing key bytes. Lookup hashes are keyed, so database exports alone do not enable guessing supplied plaintext. Master-key compromise together with database compromise permits offline guesses of low-entropy supplied values. Changing the wrap or hash info string or the salt is a format migration; changing the fingerprint info string only invalidates rotation jobs in flight.
