# 0005: Reveal and verify are mutations that write the entry only for use limits and `lastUsedAt`

## Decision

Reveal and verify are mutations. Both consume uses from the same optional `maxUses` limit in the operation's transaction; the last use marks the entry exhausted, clears its name and records an exhausted event. Missing scopes and failed verifies do not consume a use.

Without `maxUses`, reveal does not write the entry, and verify writes `lastUsedAt` only when it is absent or at least 60 seconds old. Reveal audit events are optional. Queries do not read wall-clock time.

## Consequences

Of concurrent operations on a single-use entry, Convex OCC lets exactly one succeed. A frequently used entry without `maxUses` gets no write on each reveal or verify, so its `lastUsedAt` is accurate only to 60 seconds. Entries with `maxUses` serialize on the entry row; exact consumption requires that contention. Clearing the name of revoked and exhausted entries permits reuse while keeping entry IDs and events.
