---
name: component-review
description: Review a change to @operatornest/convex-vault for defects in security boundaries, transactions, validators, bounded reads and documentation.
---

# Component review

Read `README.md`, `AGENTS.md`, the ADRs the change touches, and every changed source and test file, including new files.

Trace one call through the client, the component function, validators, schema and the example app. Check every boundary the change touches: Convex runtime portability (no Node APIs in `src/`), `VAULT_KEYS` access through generated `env`, app authentication and authorization, the `owner` binding of named references, validators, bounded indexed reads, envelope AAD, lookup hashing, transactional lifecycle, errors, exports, generated bindings and cleanup retention.

For each finding, state the file and line, the reachable behavior, its consequence and the fix. Mark each finding confirmed or unverified. After fixes, rerun the affected checks. Report `convex-test` evidence and `pnpm smoke` evidence separately.
