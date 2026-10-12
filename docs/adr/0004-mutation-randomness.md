# 0004: Generate randomness inside executing mutations

## Decision

Call WebCrypto `crypto.getRandomValues` only inside function execution, including generated values, entry/value IDs, data keys and IVs. Do not generate randomness during module import or in static initializers. `scripts/check-source.mjs` enforces the authored-source prohibition.

The Convex backend obtains a fresh execution seed from `self.rt.rng().random()` in `crates/function_runner/src/server.rs`. The isolate uses `ChaCha12Rng` in `crates/isolate/src/environment/udf/phase.rs`. The backend's `npm-packages/udf-runtime/src/00_crypto.ts` routes WebCrypto randomness to the seeded operation. Import-phase evaluation uses `import_phase_rng_seed`, a deploy-fixed seed. The execution seeding is the reason mutation-scoped randomness is required.

## Consequences

Repeated calls receive fresh generated values and encryption randomness rather than reusing import-time bytes. Generated plaintext is returned at create/replace and never stored. Source invariants and the real local-backend smoke journey verify this boundary. Backend references: [function runner](https://github.com/get-convex/convex-backend/blob/main/crates/function_runner/src/server.rs), [import and execution phases](https://github.com/get-convex/convex-backend/blob/main/crates/isolate/src/environment/udf/phase.rs) and [runtime crypto](https://github.com/get-convex/convex-backend/blob/main/npm-packages/udf-runtime/src/00_crypto.ts).
