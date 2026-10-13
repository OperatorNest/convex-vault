# 0003: Use global lookup for generated values and owner lookup for supplied values

## Decision

Generated kinds always use global lookup. Supplied kinds require an explicit lookup policy; a global supplied kind requires values at least 32 characters long. Persist storage, origin and lookup as immutable policy on a kind's first creation. Lookup HMAC input is UTF-8 JSON `["convex-vault",1,kind,lookupOwner,value]`, where global lookup uses the empty string for lookupOwner.

Create and replace probe every configured hash version in the same transaction as insertion. Current and previous values reserve uniqueness until deletion, including expired values.

## Consequences

Generated bearer credentials resolve their owner without an owner argument. Owner-lookup values never disclose a collision with another owner's value, and two owners may store the same value. Imported bearer tokens explicitly opt into global lookup. A kind cannot silently change its interpretation; use a new name for an incompatible policy. Convex OCC serializes concurrent duplicate insertion.
