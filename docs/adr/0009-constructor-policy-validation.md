# 0009: Validate kind policies when constructing the client

The `Vault` constructor validates every configured kind before any operation: kind name, storage, lookup, generation settings, explicit boolean hint and audit policy, and positive safe-integer lifecycle defaults. Generated kinds omit lookup and supplied kinds require owner or global lookup. Invalid policies throw `VAULT_INVALID_ARGUMENT` even when no credential is created or create arguments would override invalid defaults.

The client reuses the generation, expiry and use-limit checks applied by create. Constructor TTL validation checks the duration without reading the wall clock; create also checks that adding the duration to its execution timestamp remains a safe integer. Component argument validators and transactional checks protect direct callers.

Vault has no provider operations or provider-originated error codes. Its errors never include `retryable`; the shared error type defines it as true only for a transient failure whose identical call cannot create a second provider effect.
