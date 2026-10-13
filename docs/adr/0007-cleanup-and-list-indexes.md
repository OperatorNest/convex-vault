# 0007: Cleanup and list read only the rows they need

Credentials record `valuesDeletedAt` when cleanup or revoke deletes their values; a replace that renews an expired credential clears it. Cleanup reads exhausted and expired credentials whose values remain through `by_status_and_valuesDeletedAt_and_expiresAt`, and reads credentials past retention through `by_status_and_updatedAt` (revoked and exhausted, 30 days after `updatedAt`) and `by_status_and_expiresAt` (active, 30 days after `expiresAt`). `valuesDeletedAt` is internal and absent from `credentialResultValidator`.

`credentials.list` without `kind` reads `by_owner_and_createdAt` and returns credentials newest first across kinds; with `kind` it reads `by_owner_and_kind_and_createdAt`.

A cleanup run reads no credential whose work is finished, so its cost depends on the rows that still need work, not on the rows retained for renewal or audit. Revoke, cleanup and replace each write one extra field. Each credential carries two more indexes, which adds write cost to every credential insert and patch.
