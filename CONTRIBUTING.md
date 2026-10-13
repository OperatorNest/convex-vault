# Contributing

Read [README](README.md) and [AGENTS.md](AGENTS.md) first. A change to documented behavior, the storage format or a security boundary needs an ADR in `docs/adr/`.

## Setup

Development uses Node 24 and pnpm 12 through mise; consumers need Node 24 or newer.

In a fresh checkout, run in order:

```sh
mise trust && mise install
mise exec -- pnpm install --frozen-lockfile
CONVEX_AGENT_MODE=anonymous pnpm exec convex init
pnpm build:codegen
```

`build:codegen` and `smoke` use an anonymous local Convex deployment and need no login. Never
configure a cloud deployment for development.

Convex's AI files (`pnpm exec convex ai-files install`) are optional and local only. Their generated
files are gitignored; do not commit the Convex sections the installer adds to `AGENTS.md`, `CLAUDE.md`
or `convex.json`. Repository rules for agents live in `AGENTS.md`.

## Checks

```sh
pnpm check     # format, build, lint, typecheck, knip, source invariants, tests with coverage floors
pnpm smoke     # acceptance journey on a disposable local Convex backend
```

Run `pnpm smoke` for any change to component functions, schema or shared runtime code:
`convex-test` accepts calls the Convex runtime rejects, such as native `.paginate()` inside a component.

## Change requirements

- Commit messages and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`); a breaking change adds `!` after the type.
- Until 1.0.0, a breaking change ships without compatibility code, deprecation periods or data
  migrations; its changeset is a `minor` bump that states what breaks.
- Add a changeset for every consumer-visible change to `@operatornest/convex-vault`.
- Public component functions have `args` and `returns` validators; reads are bounded and indexed.
- Errors on caller-reachable paths come from `vaultError` in `src/shared/errors.ts`; add each
  `VAULT_` code, its fixed message and its README Errors row together.
- No Node built-ins, `Buffer` or `process` in `src/`. Read provider credentials and master keys
  only through generated component env; never put them in arguments, rows, logs or errors.
- Tests use generated credentials or fixed test-only vectors and stub external requests.
- Regenerate committed bindings from their inputs with `pnpm build:codegen`.
- Update affected examples, README claims and ADR contracts. Run the checks in AGENTS.md and
  report commands and exit codes.

## Encryption

Envelope encryption binds owner, kind, credential row ID, value ID and wrapped-key version in AAD. Read master keys only through generated component env; never put them in arguments, rows, logs or errors. Tests use generated master keys or fixed vectors marked as test-only.

## Bug reports

For a bug report, provide the package, Convex, and Node.js versions, deployment type (Convex Cloud, self-hosted or local), client method, storage, origin, lookup policy, operating system, a minimal reproduction, expected result, and actual result. Remove credentials (including master keys and tokens), plaintext values, lookup hashes, customer data, and personal information from reports and logs. Security reports go through [private vulnerability reporting](https://github.com/OperatorNest/convex-vault/security/advisories/new).

Follow the [OperatorNest Code of Conduct](https://github.com/OperatorNest/.github/blob/main/CODE_OF_CONDUCT.md) and [support guidance](https://github.com/OperatorNest/.github/blob/main/SUPPORT.md).

## Releasing

1. Add a changeset to each user-facing PR (`pnpm changeset`).
2. A maintainer runs `pnpm changeset version` on a branch and merges it through a PR.
3. On `main`, the Release workflow publishes a `package.json` version that is not on npm yet,
   through npm trusted publishing, after CI and smoke pass on the same commit.

Publishing, pushing, deploying and registry submissions require explicit authorization.
