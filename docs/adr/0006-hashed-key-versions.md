# 0006: Keep the original hash version of `hashed` values

Key rotation rewraps `encrypted` values and rehashes `both` values from decrypted plaintext. `hashed` values keep their original hashVersion because their plaintext is unavailable. Verify probes every configured version. Rotate in batches of 50 credentials and at most 100 values, with one rekeyed event per changed credential and a stable creation cursor.

The old master key must remain configured while any `hashed` value references it. Replace, revoke or expiry followed by cleanup releases those references. keys.getStatus reports indexed existence checks, missing versions and truncation; a truncated result is insufficient evidence to retire a key. Rehashing a hash or silently dropping an old key would make valid credentials unverifiable.
