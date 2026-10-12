---
name: changeset
description: Write or update the changeset for a change to @operatornest/convex-vault, or decide that the change needs none.
---

# Changeset

Read `package.json`, `.changeset/config.json` and the Releasing section of `CONTRIBUTING.md`.

1. Describe every consumer-visible change in one changeset: behavior, types, entry points, defaults, errors, stored data or the encryption format. State every incompatible change. Until 1.0.0, an incompatible change is a `minor` bump.
2. Update the existing changeset for the change instead of adding one per commit. A change limited to documentation, contributor guidance, templates or tests needs no changeset; state that decision in the PR.
3. Compare the changeset with the complete diff and confirm the package name, the bump and every claim. Run `pnpm check`; run `pnpm build:codegen` when component functions or the schema change, and `pnpm smoke` when runtime behavior changes.

Never put keys, credentials or personal data in a changeset.
