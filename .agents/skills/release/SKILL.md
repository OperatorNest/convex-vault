---
name: release
description: Prepare, publish and verify a release of @operatornest/convex-vault through changesets and npm trusted publishing.
---

# Release

Read `CONTRIBUTING.md`, release and CI workflows, active changesets, `package.json`, and `CHANGELOG.md`. Confirm the target branch is `main` and list every change to exported APIs.

1. Confirm release notes cover consumer-visible changes and migration steps. Run `pnpm check`, `pnpm smoke`, `pnpm audit --prod --audit-level high`, and inspect the package file list.
2. Run `pnpm changeset version` on a version branch and review package metadata, consumed changesets and `CHANGELOG.md` in a PR. CI and smoke must pass on its final commit.
3. When authorized, merge the version PR. The Release workflow builds and publishes each version not yet on npm through npm trusted publishing, then creates the tag and GitHub release.
4. Verify the published package, provenance, tag target, and release notes. Tags must match the published version's `gitHead`; never move a published tag. Report each failure with the stage where it occurred.

Publishing, tagging, pushing, and merging require explicit authorization. A passing PR does not prove publication.
