# Decisions

What was decided while building v0.1.0, and why.

## Shape

- **Framework-free, Web `Request` and `Response`.** Every runtime the MCP SDK serves from (Node,
  Deno, Bun, workers) speaks them, and Node's `http` needs only a small adapter.
- **The host owns sign-in and consent.** An authorization server that also shipped a login page
  would own the hardest part to get right for each product. `checkAuthorizeRequest` and `approve`
  are the seam: the host checks, asks, then calls `approve`, which checks everything again.
- **One config object, no product defaults.** Only the lifetimes have defaults. Claude's hosts are a
  named preset (`claudeClients`), applied only when spread in.

## Dependencies

- **`jose`, pinned exactly, and nothing else at runtime.** It does the JWT work. `zod` was not added:
  the config and request checks are small and hand-written, and a schema library would be the
  package's largest dependency.
- **Development: `typescript` and `@types/node` only.** Tests use `node:test` and Node's built-in
  coverage, and run the TypeScript sources directly (Node 22.18 or later strips types). The published
  package is compiled JavaScript with declarations, so users need only Node 22.

## The client metadata fetch

- **`node:https` rather than `fetch`.** Pinning a connection to checked addresses needs a lookup hook.
  `https.request` takes one; `fetch` needs a separate dispatcher package. So the guarded path uses
  `https.request` with a lookup that answers only the checked addresses, `agent: false`, and no
  redirect handling.
- **The unsafe option is a whole fetch, not a flag.** `unsafeFetchClientMetadata` replaces the guarded
  path with the caller's function, and its name says what it is. There is no environment check and no
  test mode. The package's own tests reach the guarded code through an internal transport seam
  (`http.request` on a local port), which is not part of the public API.
- **Refusals are pages.** Any metadata failure is `invalid_client`, as the draft says the server
  should abort the request.

## Token endpoint

- **A failing code store is `invalid_grant`; a failing grant store is `server_error`.** A code is
  single-use, so a retry could never succeed anyway, and the same answer as every other code refusal
  leaks nothing. A refresh token is still good once the store recovers, so a 500 tells the client to retry
  instead of discarding the connection.
- **A rate-limited token request answers `slow_down` with 429 and `Retry-After`.** OAuth has no
  error code for rate limiting; this keeps the behaviour of the server this was extracted from.
- **The refresh `scope` parameter is validated, never used to narrow.** The access token carries the
  grant's scopes. Narrowing per refresh is allowed by RFC 6749 but no MCP client was seen to use it.
- **The key is checked before anything is spent.** A burnt code the server could not turn into a
  token would cost the person a reconnect for the server's own gap.

## Tokens and grants

- **No email claim by default.** A bearer token ends up in logs and client storage.
- **Exactly one audience, and a maximum age.** jose accepts an audience array that merely contains
  ours, and checks `exp` as written; a token minted with a longer `exp` still dies on schedule.
- **Refresh reuse is configurable.** Revoking the family is the safer default, and it can sign a person
  out after a retried refresh; some deployments prefer the other trade (SECURITY-MODEL.md).
- **`isGrantActive` instead of built-in account checks.** The server this was extracted from
  re-checked tenant membership, account verification and a revocation cutoff on every refresh.
  Those are product rules, so the package asks one hook, at the code exchange and every refresh,
  with `authorizedAt` so a cutoff can be compared.
- **`context` instead of a fixed tenant field.** The original bound every grant to one tenant.
  The package carries a string map from `approve` to the grant, the hooks and the claims hook.

## The example server

- **The MCP SDK's current line, v2.** The official TypeScript SDK ships v2 as split packages
  (`@modelcontextprotocol/server`, `@modelcontextprotocol/client`); `@modelcontextprotocol/sdk` is
  the v1 line, maintained on a branch. The example pins v2 exactly, and serves both protocol eras
  through `createMcpHandler`, so 2025-era clients connect too.
- **No framework, no SDK middleware package.** A small adapter (`src/node-http.ts`) turns
  `node:http` into Web `Request` and `Response`, which both mcp-frontdesk and the SDK's handler take.
- **Its own lockfile, linked to the checkout.** `mcp-frontdesk` is a `file:../..` dependency, so
  the example runs against the package as built, and the root package stays free of the SDK.
- **The end-to-end test uses the unsafe fetch, and says why.** A client_id is https on port 443,
  and the SSRF guard refuses loopback addresses whatever resolver is injected, so a document served
  by the test on loopback is reachable only through `unsafeFetchClientMetadata`. The test restricts
  it to one host and checks separately that the guarded default refuses the same setup.

## Not carried over from the original

- **Account and tenant checks** (membership, verified account, sessions cutoff, owner-only scopes):
  product rules, now the `isGrantActive` hook and the host's own handler.
- **Deployment routing of codes and tokens**: replaced by the generic `tokenWrapper`.
- **Error reporting and logging integrations**: replaced by `reporter` and `audit`.
- **A storage backend**: replaced by the two store interfaces and the contract suite.
- **The connected-apps page's client labels**: product copy.
- **Feature flags on scopes**: a host advertises the scopes it configures.
