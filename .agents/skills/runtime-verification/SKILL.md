---
name: runtime-verification
description: Choose and run the checks that prove a change to @operatornest/convex-vault, from unit tests to the local-backend smoke journey.
---

# Runtime verification

Read `AGENTS.md`, the `scripts` in `package.json`, and `scripts/smoke.mjs`.

1. Run the affected tests, including client and example tests for consumer behavior, then `pnpm check`.
2. For changes to component functions, the schema or the generated API, run `CONVEX_AGENT_MODE=anonymous pnpm exec convex init` once per checkout, then `pnpm build:codegen` and `pnpm smoke`. Commit regenerated bindings with the source that produced them; never edit generated files.
3. For a code example in documentation, run its code path or the closest test, then `pnpm fmt:check`. A prose-only change needs only `pnpm fmt:check`.
4. `convex-test` proves component logic; only `pnpm smoke` proves behavior in the Convex runtime. Neither has run against Convex Cloud; state that limit when it matters.

The vault calls no external provider, so the repository has no `pnpm e2e`. Scripts serialize local backend access through a shared lock; never stop another checkout's backend.
