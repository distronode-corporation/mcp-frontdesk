# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-15

### Added

- `createFrontdesk`: discovery documents (RFC 8414, RFC 9728), authorization-request checks with
  Client ID Metadata Documents and PKCE S256, `approve` and `denialUrl` for the host's consent page,
  the token endpoint (`authorization_code` and `refresh_token` with rotation and reuse detection),
  `listGrants` and `revokeGrant`, and the bearer gate with 401 and 403 step-up challenges.
- An SSRF guard on the client metadata fetch: internal names refused, one resolution, private ranges
  refused, the connection pinned, no redirects, 5 seconds, 5 KB.
- `MemoryCodeStore` and `MemoryGrantStore`, and the store contract suite in `mcp-frontdesk/testing`.
- `keyProviderFromJwk`, `generateSigningJwk` and `publicJwk` for ES256 keys.
- The `claudeClients` preset.
- `mcp-frontdesk/experimental`: `createFence` for fencing untrusted text.
- `examples/basic-server` (not published): a runnable server on `node:http` with the official MCP
  TypeScript SDK, a demo sign-in and consent page, and an end-to-end test.

### Changed

These change behaviour that earlier pre-release builds of this branch had. Nothing was published
before 0.1.0.

- `CodeRecord` gains a required `authorizedAt`: the time the person approved access. It travels
  with the authorization code into the grant, so `isGrantActive` sees the consent time, not the
  exchange time. A custom `CodeStore` must now persist `authorizedAt` with the rest of the record.
- `sameResource` matches the resource indicator exactly, so an explicit `:443` (as in
  `https://mcp.example.com:443/mcp`) no longer matches `https://mcp.example.com/mcp`.
- Node.js 22.18 or later is required (`engines`), the oldest version the test matrix runs (22.18,
  then the latest 22 and 24, on Linux, macOS and Windows).
- `CodeStore` gains a tombstone for spent codes, so a replayed authorization code revokes the family
  its first redemption started (RFC 6749 section 4.1.2), still answered with `invalid_grant`.
  `take(codeHash, spent)` now takes a `SpentCode` (the family id, and a tombstone lifetime of the
  code's lifetime plus 10 minutes) and, when it returns the record, must leave that tombstone in the
  same atomic step; new `markReplayed(codeHash)` and `wasReplayed(codeHash)` flag and read it. A
  custom `CodeStore` must implement all of this; `createFrontdesk` refuses one that lacks the new
  methods, and the contract suite has cases for it. New audit event `code.replayed`, and the
  `grant.revoked` reason `code_reuse`.
- A grant family has an absolute lifetime: `maxFamilyLifetimeSeconds`, default 30 days
  (`DEFAULT_MAX_FAMILY_LIFETIME_SECONDS`), counted from the first sign-in. A refresh at or after it
  is refused with `invalid_grant` and revokes the family (`grant.revoked` reason `family_expired`),
  and no row's expiry runs past it. `GrantRecord` and `NewGrant` gain a required `familyCreatedAt`,
  the same on every row of a family: a custom `GrantStore` must persist it, and the contract suite
  checks it.
- A refresh request whose `scope` names a resource scope the grant does not hold is refused with
  `invalid_scope` (RFC 6749 section 6), decided only after the refresh token passed every check.
  It used to be ignored. A scope the server does not define at all is still `invalid_scope` before
  the token is looked up, as before. The grant's scopes, or fewer, still work, and are not narrowed.
- `maxFamilyLifetimeSeconds` is at most 365 days (`MAX_FAMILY_LIFETIME_SECONDS`); `createFrontdesk`
  refuses a larger value.
- `approve` fails closed when a hook throws (the clock included): reported, and answered
  `{ ok: false, kind: "unavailable" }` with no code minted, instead of the error escaping.
- The client metadata deadline aborts with a `TimeoutError` reason, and cancels a body still being
  read even when the host's fetch ignores the signal.
- `resourcePaths` entries the URL parser cannot read are refused with `FrontdeskConfigError`, not a
  raw `TypeError`.
- `codeStoreContract` checks that a tombstone lasts the lifetime `take` gave it, and takes an
  optional `{ sleep }` for stores on a test-controlled clock.
- The SSRF guard also refuses 192.88.99.0/24 (the deprecated 6to4 relay anycast block) and
  2001:10::/28 (ORCHIDv1).
