---
"@operatornest/convex-vault": minor
---

Remove the `credentialValidator` export; the client exports an explicit list of argument and result validators.
Require `auditRevealsKinds` on the component `credentials.reveal` function; the client sends every configured kind whose current `auditReveals` is true.
Rename example wrappers `listEvents`, `keyStatus` and `rotateKeys` to `eventsList`, `keysGetStatus` and `keysRotate`.
Order `credentials.list` without `kind` newest first by `createdAt` across kinds.
Replace the credentials index `by_expiresAt` with `by_status_and_expiresAt` and add `by_owner_and_createdAt` and `by_status_and_valuesDeletedAt_and_expiresAt`.
Audit a reveal when the client's current or the credential's stored `auditReveals` is true.
Make each cleanup run read only credentials whose values remain or whose retention has ended, and clean a renewed credential again after its renewed expiry.
Reject an oversized `actor` on every reveal, replace and revoke, whether or not an event is written.
Report more than two values per credential as an internal error instead of `VAULT_INVALID_ARGUMENT`.
Export `keyStatusResultValidator` and `KeyStatusResult`, and use them as the `keys.getStatus` result.
Unwrap each data key once during rotation and derive each wrap and hash key once per function call.
