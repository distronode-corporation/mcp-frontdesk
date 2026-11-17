# Contributing

Thank you for helping. Some ground rules keep the package small and trustworthy.

## Principles

- **Fail closed.** When a check cannot be completed (a store error, a missing key, a hook that
  throws), refuse. Never issue a code or a token on a path that skipped a check.
- **No oracle.** Every refusal of a code or a refresh token at the token endpoint stays the same
  `invalid_grant`. Reasons go to the audit sink.
- **No test-mode bypasses.** Tests inject what they need (a resolver, a clock, a store).
- **No product defaults.** Anything a host might differ on is configuration.
- **Runtime dependencies are pinned exactly.** Today that is `jose`. Adding one needs a very good
  reason, written down in `DECISIONS.md`.
- **TypeScript with erasable syntax only**, so Node runs the sources directly in tests.

## Setup

Node.js 22.18 or later (the tests run the TypeScript sources with Node's type stripping).

```sh
npm ci
npm run lint
npm run typecheck
npm run test:coverage   # 100% lines, branches and functions on src/, enforced
npm pack --dry-run

# The example server and its end-to-end test, against the build above
npm run build
cd examples/basic-server && npm ci && npm run typecheck && npm test
```

## Style

Code follows oxlint's `correctness` rules (oxlint's own rules and its ports of the ESLint,
typescript-eslint and unicorn rules, for code that is outright wrong), configured in `.oxlintrc.json`, and TypeScript's
`strict` mode with the extra checks in `tsconfig.json`. Formatting follows `.editorconfig`. CI
runs `npm run lint` (warnings fail it too) and `npm run typecheck` in every test job, and a pull
request that fails either does not merge. A rule is never switched off for one line to make a
change pass; fix the code, or argue for changing the config in the pull request.

## Tests

- A pull request that adds or changes functionality adds tests for it to the automated suite, and
  a bug fix adds a test that fails without the fix. The 100% coverage floor makes the first half
  hard to skip; the second half is on the reviewer.
- The tests run with `--throw-deprecation`, so a call to a deprecated Node.js API fails them.
- A flaky test is a bug. Fix the cause; do not add retries or loosen assertions.
- Tests never touch the network: client metadata comes from an injected fetch or a local server.

## Changes

- Update `SPEC.md` when behaviour changes, and `CHANGELOG.md` for anything user-visible.
- Use only synthetic examples: `example.com`, `https://mcp.example.com/mcp`, `user-1`. Never include
  real hosts, account ids, tokens or keys.
- Security issues go through private vulnerability reporting (see `SECURITY.md`), not public issues.

## Commits and pull requests

There is no Developer Certificate of Origin sign-off requirement. By opening a pull
request you agree that your contribution is licensed under the Apache License, Version
2.0, as section 5 of that licence describes.

Documentation moves with the code: a pull request that changes behaviour changes the README,
`SPEC.md` or `SECURITY-MODEL.md` that describes it in the same pull request. A known mismatch
between the docs and the code is a bug; open an issue for it.

The project's roles, and how a change is accepted, are in the organization's
[GOVERNANCE.md](https://github.com/distronode-corporation/.github/blob/main/GOVERNANCE.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
