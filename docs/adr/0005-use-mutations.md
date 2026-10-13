# 0005: Reveal and verify are mutations that write the credential only for use limits and `lastUsedAt`

## Decision

Reveal and verify are mutations. Both consume uses from the same optional `maxUses` limit in the operation's transaction; the last use marks the credential exhausted, clears its name and records an exhausted event. Missing scopes and failed verifies do not consume a use.

Without `maxUses`, reveal does not write the credential, and verify writes `lastUsedAt` only when it is absent or at least 60 seconds old. Reveal audit events are optional. Queries do not read wall-clock time.

## Consequences

Of concurrent operations on a single-use credential, Convex OCC lets exactly one succeed. A frequently used credential without `maxUses` gets no write on each reveal or verify, so its `lastUsedAt` is accurate only to 60 seconds. Credentials with `maxUses` serialize on the credential row; exact consumption requires that contention. Clearing the name of revoked and exhausted credentials permits reuse while keeping credential IDs and events.
