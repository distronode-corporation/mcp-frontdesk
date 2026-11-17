# Decisions

What was decided while building v0.1.0, and why.

## Shape

- **Framework-free, Web `Request` and `Response`.** Every runtime the MCP SDK serves from (Node,
  Deno, Bun, workers) speaks them, and Node's `http` needs only a small adapter.
- **The host owns sign-in and consent.** An authorization server that also shipped a login page
  would own the hardest part to get right for each product. `checkAuthorizeRequest` and `approve`
  are the seam: the host checks, asks, then calls `approve`, which checks everything again.
- **One config object, no product defaults.** What has a default is either derived from the host's
  own values (`defaultScopes` is all of `scopes`, `resourcePaths` is the resource's path) or a
  security parameter (the lifetimes, `refreshTokenReuse: "revoke-family"`, `allowLoopbackRedirects:
  false`). Claude's hosts are a named preset (`claudeClients`), applied only when spread in.

## Dependencies

- **`jose`, pinned exactly, and nothing else at runtime.** It does the JWT work. `zod` was not added:
  the config and request checks are small and hand-written, and a schema library would be the
  package's largest dependency.
- **Development: `typescript` and `@types/node` only.** Tests use `node:test` and Node's built-in
  coverage, and run the TypeScript sources directly (Node 22.18 or later strips types). The published
  package is compiled JavaScript with declarations, but `engines` still says `>=22.18`: that is the
  oldest Node the CI runs the package on, and a range that names versions no test ever ran would be
  a claim nobody checked.

## The client metadata fetch

- **`node:https` rather than `fetch`.** Pinning a connection to checked addresses needs a lookup hook.
  `https.request` takes one; `fetch` needs a separate dispatcher package. So the guarded path uses
  `https.request` with a lookup that answers only the checked addresses, `agent: false`, and no
  redirect handling.
- **One deadline covers the body too, and it cancels.** When the 5 seconds pass, the signal aborts
  with a `TimeoutError` reason (so a host's fetch can tell a timeout from a cancel), and a body
  still being read is cancelled with that reason, even when the host's fetch ignores the signal. A
  stalled body is let go of instead of holding a read open after the refusal.
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
- **The refresh `scope` parameter is checked, never used to narrow.** A scope beyond the grant is
  `invalid_scope` (RFC 6749 section 6 says it MUST NOT be included); the grant's scopes or fewer are
  accepted, and the access token carries the grant's scopes (less any the config has since removed,
  below). Narrowing per refresh at the client's request is allowed by RFC 6749 but no MCP client was
  seen to use it.
- **`invalid_scope` on a refresh comes after every check of the token.** The rule is that a refusal
  of a code or a grant never says why. The grant's scopes are known only once its row is found, so
  answering `invalid_scope` as soon as the row is found would tell a caller that a rotated, revoked
  or expired token once existed, and answering it partway through the checks would reveal which of
  them a token passed. Deciding it last means only a token that would have refreshed sees
  `invalid_scope`, and a rotated token presented with a wider scope is still reuse (and revokes its
  family under the default policy). Scopes this server does not recognise at
  all are refused before the token is looked up, because that answer depends on nothing but the
  request.
- **A replayed code revokes its family, through a tombstone in the code store.** RFC 6749 section
  4.1.2 says the server SHOULD revoke what a code issued when the code is used twice. The token
  endpoint chooses the family id before the take; the take leaves a tombstone naming it in the same
  atomic step; a replay's take finds no record and asks `markReplayed`. A replay can land between
  the first redemption's take and its grant insert, when there is no family yet to revoke, so the
  replay also flags the tombstone and the first redemption checks the flag after its insert. Every
  ordering of the two then ends with the family revoked and no token handed out on the late side.
  The cost is one extra code store read per successful exchange.
- **The tombstone lives for the code's lifetime plus 10 minutes** (11 minutes at the default 60 s).
  A legitimate redemption and any replay both happen while the code is valid; after that the code
  is refused as expired anyway. The 10 minutes cover clock skew between instances and a slow retry,
  and keep the store at one small entry per sign-in for minutes, not days. It is a constant, not a
  setting: a shorter one would only weaken the check, and a longer one buys nothing.
- **A code store without the tombstone is refused at startup, not tolerated.** The tombstone could
  have been optional (revoke when the store supports it). That would make the protection silently
  absent for exactly the hosts that wrote their own store before it existed, and nothing would ever
  say so. `createFrontdesk` instead throws `FrontdeskConfigError` when `markReplayed` or
  `wasReplayed` is missing, and the contract suite checks that they work. The package was not yet
  published when this was decided, so no adopter was broken by the requirement. At run time the check fails closed too: a
  `markReplayed` that throws is the same `invalid_grant` (reported), and a `wasReplayed` that throws
  revokes the new family and refuses.
- **A removed scope narrows a grant; it does not end it.** When the config drops a scope, a refresh
  (or a code approved earlier) is answered with the scopes still configured, and the `scope` field
  says so: RFC 6749 lets the server issue less than was asked (section 3.3), and a refresh may never
  carry more than the original grant (section 6). Refusing would sign every connected person out for
  a config change that did not concern most of them. The successor grant keeps the narrowed set, so
  a scope that comes back later needs a new consent. A grant left with no scope can never mint
  again, so it is refused with `invalid_grant` and its family revoked (audit reason `no_scope`).
- **The access token is minted before the store is written.** Every check that can fail, the mint
  included, runs before `GrantStore.rotate` (or `insert`). A claims hook that throws then costs a
  retry, never the refresh token. A token minted for a rotation that loses
  its race is dropped unsent.
- **`approve` fails closed on a hook that throws.** A key provider, a store, the clock or the
  metadata fetch that throws is reported and answered `{ ok: false, kind: "unavailable" }`, with no
  code minted, as the token endpoint answers a failing hook with a refusal. Misuse of `approve`
  itself (no subject, params that are not an object, scopes outside the request, non-string
  context) still throws `TypeError`: that is a bug in the host to fix, not a fault to ride out.
- **The key is checked before anything is spent, once.** A burnt code the server could not turn into
  a token would cost the person a reconnect for the server's own gap. The key fetched for that check
  is the one that signs, so a provider that answers once and then fails cannot burn the code between
  the two.

## Tokens and grants

- **No email claim by default.** A bearer token ends up in logs and client storage.
- **Exactly one audience, and a maximum age.** jose accepts an audience array that merely contains
  ours, and checks `exp` as written; a token minted with a longer `exp` still dies on schedule.
- **Refresh reuse is configurable.** Revoking the family is the safer default, and it can sign a person
  out after a retried refresh; some deployments prefer the other trade (SECURITY-MODEL.md).
- **A family has an absolute lifetime, `maxFamilyLifetimeSeconds`, 30 days by default.** The refresh
  lifetime slides on every rotation, so without a cap a family refreshed at least once a month never
  ends, and a stolen copy that is never caught (under `"refuse"`, or before the client's next
  refresh) lives as long as the thief keeps refreshing. The cap is counted from `familyCreatedAt`,
  the code exchange, which every row of the family carries. A refresh at or after the end is refused
  with the same `invalid_grant` and revokes the family, so the connection disappears from
  `listGrants` at once rather than lingering until a row expires; each row's own expiry is also
  capped at the end. 30 days bounds a stolen family to a month and costs a person one sign-in a
  month per client, which suits a connector people approve once and use daily; a host that wants
  fewer sign-ins can raise it, and one that wants tighter control can lower it. It is counted from
  the exchange, not from consent (`authorizedAt`), because the two differ by at most the code's
  lifetime and the family is what the cap bounds.
- **`maxFamilyLifetimeSeconds` is at most 365 days, and a larger value is refused at
  `createFrontdesk`.** Checked like the other lifetimes (a positive integer of seconds), with a
  ceiling: a family allowed to live longer than a year is not bounded in any useful sense, and an
  astronomically large value would push the computed end past what a Date can hold, so the family
  would never end. Refusing is the fail-closed answer; clamping would quietly run a different
  configuration from the one written.
- **`isGrantActive` instead of built-in account checks.** The server this was extracted from
  re-checked tenant membership, account verification and a revocation cutoff on every refresh.
  Those are product rules, so the package asks one hook, at the code exchange and every refresh,
  with `authorizedAt` so a cutoff can be compared. `authorizedAt` is the moment of consent, carried
  in the code (`CodeRecord.authorizedAt`), not the moment the client redeemed it: a password reset
  between the two must still end the grant.
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
