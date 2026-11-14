# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

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
