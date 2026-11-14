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
npm run typecheck
npm run test:coverage   # 100% lines, branches and functions on src/, enforced
npm pack --dry-run
```

- A flaky test is a bug. Fix the cause; do not add retries or loosen assertions.
- Tests never touch the network: client metadata comes from an injected fetch or a local server.

## Changes

- Update `SPEC.md` when behaviour changes, and `CHANGELOG.md` for anything user-visible.
- Use only synthetic examples: `example.com`, `https://mcp.example.com/mcp`, `user-1`. Never include
  real hosts, account ids, tokens or keys.
- Security issues go through private vulnerability reporting (see `SECURITY.md`), not public issues.

By contributing, you agree that your contributions are licensed under the Apache License 2.0.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
