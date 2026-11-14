# mcp-frontdesk

A small OAuth 2.1 authorization server and access-token gate for MCP servers. It signs people
in to your MCP server the way the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
asks: clients identify themselves with a Client ID Metadata Document, every code needs PKCE
S256, and refresh tokens rotate on every use.

- Framework-free: every endpoint takes a Web `Request` and returns a `Response`.
- One runtime dependency, [`jose`](https://github.com/panva/jose). TypeScript, ESM, Node.js 22.18 or later.
- Your storage, behind two small interfaces. In-memory stores ship in the package, and a contract
  test suite (`mcp-frontdesk/testing`) checks yours.
- No product defaults. You configure every URL, scope, client host and redirect URI.

mcp-frontdesk began as the sign-in layer of Distronode's own MCP server, the one behind the
District AI connector for Claude. We pulled it out so any MCP server can run its own authorization.

> **Status: 0.1.0.** The API may still change before 1.0. Read [SECURITY-MODEL.md](SECURITY-MODEL.md)
> before you put it in front of real accounts.

Contents: [When to use it](#when-to-use-it) · [Quick start](#quick-start) ·
[What it serves](#what-it-serves) · [Configuration](#configuration) · [Storage](#storage) ·
[Safety properties](#safety-properties) · [What a RateLimiter protects](#what-is-not-protected-without-a-ratelimiter) ·
[Example server](#example-server) · [Experimental: fencing untrusted text](#experimental-fencing-untrusted-text) ·
[What it does not do](#what-it-does-not-do)

## When to use it

The official MCP TypeScript SDK handles the protocol. For authorization, its server side is the
resource-server half: a bearer gate (`requireBearerAuth`) around a token verifier you supply, and
the protected resource metadata. Its own authorization-server helpers are frozen in a legacy
package, and its documentation tells new servers to use a dedicated identity provider.

That is the right answer if you already run an identity provider that speaks Client ID Metadata
Documents. mcp-frontdesk is for when you want to be your own authorization server: your accounts,
your consent page, your database, and nothing else in between.

| | Official SDK | mcp-frontdesk |
|---|---|---|
| MCP protocol, transports, tools | Yes | No: use the SDK |
| Bearer gate and 401/403 challenges | Yes | Yes |
| Protected resource metadata (RFC 9728) | Yes | Yes |
| Authorization server: metadata, authorize checks, codes, token endpoint | Legacy package only | Yes |
| Client ID Metadata Documents, fetched behind an SSRF guard | No | Yes |
| Refresh-token rotation with reuse detection | No | Yes |
| Sign-in and consent UI | No | No: yours |

The two work together: mcp-frontdesk's `authenticate` gates the route, and the SDK serves MCP behind it.

## Quick start

```sh
npm install mcp-frontdesk
```

```ts
import {
  claudeClients,
  createFrontdesk,
  keyProviderFromJwk,
  MemoryCodeStore,
  MemoryGrantStore,
} from "mcp-frontdesk";

const frontdesk = createFrontdesk({
  ...claudeClients, // Claude's client hosts and callbacks; leave it out to accept only your own clients
  issuer: "https://mcp.example.com",
  resource: "https://mcp.example.com/mcp",
  scopes: ["notes:read", "notes:write"],
  defaultScopes: ["notes:read"],
  authorizationEndpoint: "/authorize",
  tokenEndpoint: "/token",
  allowedOrigins: [],
  keys: await keyProviderFromJwk(signingJwk), // a P-256 private JWK from your secret store
  codeStore: new MemoryCodeStore(), // single process only; see Storage
  grantStore: new MemoryGrantStore(),
});

export async function handle(request: Request): Promise<Response> {
  const discovery = frontdesk.handleDiscovery(request);
  if (discovery) return discovery;

  const { pathname } = new URL(request.url);
  if (pathname === "/token") return frontdesk.handleToken(request);
  if (pathname === "/authorize") return consent(request);
  if (pathname === "/mcp") {
    const auth = await frontdesk.authenticate(request);
    if (!auth.ok) return auth.response; // 401 with resource_metadata, or 403
    return serveMcp(request, auth.token); // the MCP SDK; auth.token.subject is the person
  }
  return new Response("Not found", { status: 404 });
}
```

The consent page is yours. mcp-frontdesk checks the request; you sign the person in and ask them:

```ts
async function consent(request: Request): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const check = await frontdesk.checkAuthorizeRequest(params);
  if (!check.ok) {
    // "page" errors must never redirect: the client or its redirect_uri is not verified.
    return check.kind === "page" ? errorPage(check.error) : Response.redirect(check.redirectUrl, 302);
  }
  const person = await signedInPerson(request); // your session; null sends them to sign in
  if (!person) return redirectToSignIn(request);

  if (request.method === "GET") {
    // Show check.request.clientHost (who is asking, as your allowlist vouches),
    // clientName beside it, redirectHost, and the scopes. Warn when loopback is true.
    return renderConsentPage(check.request);
  }

  // POST from your consent form, with your own CSRF protection.
  if (!(await userPressedApprove(request))) return Response.redirect(frontdesk.denialUrl(check.request), 302);
  const result = await frontdesk.approve({ params, subject: person.id, context: { tenant: person.tenantId } });
  if (!result.ok) return result.kind === "redirect" ? Response.redirect(result.redirectUrl, 302) : errorPage("try_again");
  return Response.redirect(result.redirectUrl, 302); // code, state and iss
}
```

`approve` checks the whole request again and mints a single-use code. Nothing is minted on a
page load.

To make a key for development:

```ts
import { generateSigningJwk } from "mcp-frontdesk";
const signingJwk = await generateSigningJwk(); // store it as a secret; never commit it
```

## What it serves

| Call | What |
|---|---|
| `handleDiscovery(request)` | `/.well-known/oauth-protected-resource<path>` and the root form (RFC 9728), `/.well-known/oauth-authorization-server` (RFC 8414). Null for any other path. |
| `checkAuthorizeRequest(params)` | Validates an authorization request in a fixed order (client, redirect, then the rest). |
| `approve({ params, subject, scopes?, context? })` | After your consent page says yes: checks again, mints a code, answers the redirect URL. |
| `denialUrl(request)` | The `access_denied` redirect for a "no". |
| `handleToken(request)` | The token endpoint: `authorization_code` with PKCE S256, and `refresh_token`. |
| `listGrants(subject)` / `revokeGrant(subject, familyId)` | One entry per connection, for a "connected apps" page. A revoke takes effect at the next refresh. |
| `authenticate(request, { requiredScopes? })` | The bearer gate for the MCP route. |
| `unauthorized(presented)` / `insufficientScope(scopes)` | The challenges, for a host that refuses on its own. |

## Configuration

`createFrontdesk(config)` checks the config once and throws `FrontdeskConfigError` for anything
unusable. Required:

| Field | Meaning |
|---|---|
| `issuer` | The authorization server's identifier. https, canonical (http is accepted only on `localhost`, `127.0.0.1` or `[::1]`). |
| `resource` | The MCP server's canonical URI. The audience of every token. |
| `scopes` | The resource's scopes. `offline_access` is recognised in requests without being listed. |
| `authorizationEndpoint`, `tokenEndpoint` | A path under the issuer's origin (`//host/...` is refused), or an absolute URL. |
| `clientIdHosts` | Hosts whose Client ID Metadata Documents are accepted, exact names. |
| `redirectUris` | Exact hosted callbacks a client document may list. |
| `allowedOrigins` | Browser origins allowed at the token endpoint and the gate. Any other `Origin` is refused. Requests with no `Origin` are not affected. |
| `keys`, `codeStore`, `grantStore` | Your adapters. |

Optional:

| Field | Default | Meaning |
|---|---|---|
| `defaultScopes` | all of `scopes` | Granted when a request names none. |
| `resourcePaths` | the resource's path | Request paths a token may be used on: canonical absolute paths, no query or fragment. |
| `resourceName` | none | `resource_name` in the resource metadata. |
| `allowLoopbackRedirects` | `false` | Accept `http://localhost`, `127.0.0.1`, `[::1]` redirects on any port (native clients). |
| `ttl.authorizationCode` | 60 s | Code lifetime. |
| `ttl.accessToken` | 600 s | Access-token lifetime, and its maximum age at verification. |
| `ttl.refreshToken` | 30 days | Sliding: reset on every rotation, never past the family's end. |
| `maxFamilyLifetimeSeconds` | 30 days | Absolute: a connection ends this long after its first sign-in, however often it refreshes. The person signs in again. At most 365 days; a larger value is refused. |
| `refreshTokenReuse` | `"revoke-family"` | Or `"refuse"`. See below. |
| `accessTokenClaims(grant)` | none | Extra claims. Registered claims cannot be set. |
| `isGrantActive(grant)` | none | Asked at the code exchange and every refresh. False ends the grant. |
| `tokenWrapper` | none | Routes codes and refresh tokens across deployments. See below. |
| `rateLimiter`, `reporter`, `audit` | none | See below. |
| `clientMetadata.resolveHost` | system resolver | The SSRF guard still checks every address. |
| `clientMetadata.unsafeFetchClientMetadata` | none | Replaces the guarded fetch. See safety property 1. |

`claudeClients` is a named preset, never applied unless you spread it in: the hosts `claude.ai`
and `claude.com`, the callbacks `https://claude.ai/api/mcp/auth_callback` and
`https://claude.com/api/mcp/auth_callback`, and loopback redirects for Claude Code.

## Storage

You implement two interfaces (`CodeStore`, `GrantStore`, in `stores.ts`). Stores only ever see
SHA-256 hashes, never a code or a refresh token.

- `CodeStore.take` must be atomic: of concurrent calls for one hash, at most one gets the record.
  The call that gets it also leaves a tombstone, in the same step, naming the family the redemption
  starts, for the code's lifetime plus 10 minutes. `markReplayed` flags that tombstone and answers
  its family; `wasReplayed` reads the flag. That is how a replayed code revokes what its first
  redemption issued. `createFrontdesk` refuses a code store without these methods.
- `GrantStore.rotate` must claim the row and insert its successor as one unit, and refuse when the
  row or any row of its family is revoked. `revokeFamily` must also catch a successor that a racing
  rotation inserted. Every row keeps `familyCreatedAt` as written: the family's absolute lifetime
  is counted from it.

`MemoryCodeStore` and `MemoryGrantStore` are correct for one process and lose everything on
restart. For anything else, write your own and run the contract suite against it in your tests:

```ts
import { codeStoreContract, grantStoreContract } from "mcp-frontdesk/testing";
import { test } from "node:test"; // or vitest, or jest

for (const c of codeStoreContract(() => new MyCodeStore())) test(c.name, c.run);
for (const c of grantStoreContract(() => new MyGrantStore())) test(c.name, c.run);
```

The suite fires concurrent calls, so a take or rotate written as a read followed by a separate write
fails it. One case waits most of a second on the wall clock, to check that a spent code's tombstone
lasts the lifetime it was given; a store on a clock your test controls can pass
`codeStoreContract(make, { sleep })` with a `sleep` that moves that clock instead. This repository
runs the suite against the in-memory stores on every commit.

## Safety properties

Each one is pinned by tests in `test/`.

1. **The client metadata fetch goes through an SSRF guard, on by default.** An unauthenticated
   visitor chooses the client_id URL, so the fetch refuses internal names, resolves the host once,
   refuses any private, loopback, link-local, site-local, shared or reserved address (IPv6 forms that
   embed one included), connects only to the addresses it checked, never follows a redirect, and gives
   up after 5 seconds (one deadline for the lookup and the whole fetch) or 5 KB. There is no test-mode bypass: tests inject a resolver. A raw fetch is accepted
   only through `clientMetadata.unsafeFetchClientMetadata`, which skips the guard (the deadline, the
   cap and every document check still apply). Use it only when every allowed client host is yours.
2. **Body caps are streaming.** The token request (8 KB) and the metadata document (5 KB) are read
   chunk by chunk and cut off at the first chunk that crosses the cap; a declared length over the cap
   is refused before reading.
3. **No oracle at the token endpoint.** Every refusal of a code or a refresh token is the same
   `invalid_grant`: unknown, replayed, expired, wrong client, wrong redirect, wrong verifier, inactive.
   The reason goes to your audit sink only. A code store that fails is a refusal, never a token. A
   code is spent by the first well-formed request that presents it, right or wrong. A request
   refused before the code store is asked (a missing field, another `resource`, a verifier too
   malformed to ever match, no signing key) leaves the code where it was. A spent code presented
   again is answered with the same `invalid_grant`, and revokes the family its first redemption
   started (RFC 6749 section 4.1.2), even when that replay lands while the first redemption is
   still in flight. A refresh that names a resource scope the grant never had gets `invalid_scope`,
   but only once the refresh token has passed every check, so a dead token gets `invalid_grant`
   whatever resource scope it names. A scope this server does not define at all is `invalid_scope`
   before the token is looked up, which says nothing about the token.
4. **Refresh tokens rotate on every use.** By default, a rotated token presented again revokes its
   whole family, the successor included: reuse is indistinguishable from theft. That has a cost: a
   client that lost a refresh response and retries with the old token signs its person out. With
   `refreshTokenReuse: "refuse"`, only the reused token is refused and the successor keeps working.
   A thief who refreshes first can then keep refreshing until `maxFamilyLifetimeSeconds` (30 days
   by default) after the first sign-in, unless the family is revoked before that or goes
   `ttl.refreshToken` without a refresh; the last access token minted then works for up to
   `ttl.accessToken` more. The current token of a family, presented by a
   different client, revokes the family in both modes. See [SECURITY-MODEL.md](SECURITY-MODEL.md).
5. **No email in access tokens by default.** A token carries `sub`, `client_id`, `scope` and the
   registered claims. Add anything else with `accessTokenClaims`.
6. **A wrap hook for codes and refresh tokens.** A host running several deployments can decorate
   what it hands out, with a routing label a load balancer reads, for example, and refuse values that
   belong elsewhere without a lookup (`tokenWrapper.unwrap` returning null). Only the bare value is
   hashed and stored.
7. **A RateLimiter is optional, and its absence is stated plainly below.**

### What is not protected without a RateLimiter

mcp-frontdesk calls `rateLimiter.allow(endpoint, request)` at the token endpoint (`"token"`) and the
gate (`"resource"`). A limiter that throws fails closed: it is reported, and the request is refused
(503 at the gate, 500 at the token endpoint). With no `rateLimiter`, nothing limits:

| Surface | What a flood costs you |
|---|---|
| Token endpoint | A code-store take or a grant-store read per request. Codes and refresh tokens are 256-bit random values, so guessing is not the risk; load is. |
| The gate | One signature verification per request. |
| Your consent page and approve route | They are yours: mcp-frontdesk does not see their requests. Each check of a new client_id can fetch a metadata document (cached for good documents, never for refusals), so an unlimited consent page lets anyone make your server send outbound requests to allowed hosts. Limit it. |
| `listGrants`, `revokeGrant` | Yours to limit, per account. |

## Example server

[`examples/basic-server`](examples/basic-server) is a runnable MCP server on plain `node:http`:
mcp-frontdesk for OAuth and the bearer gate, the official MCP TypeScript SDK
(`@modelcontextprotocol/server`) for the protocol, a plain-HTML consent page behind a demo sign-in
(pick an account, no password), in-memory stores, and three tools over made-up notes:
`list_notes` and `read_note`, which need the `notes:read` scope, and `add_note`, which needs
`notes:write`. It listens on
`127.0.0.1` over http, which mcp-frontdesk accepts for a loopback issuer and resource, and refuses
any other `Host` header. It is not part of the published package.

```sh
git clone https://github.com/distronode-corporation/mcp-frontdesk.git
cd mcp-frontdesk
npm ci && npm run build          # the example uses this checkout's build
cd examples/basic-server
npm ci
npm start                        # serves http://127.0.0.1:3000/mcp (PORT=4000 npm start for another port)
npm test                         # the end-to-end test
```

`npm start` accepts the clients in the `claudeClients` preset and fetches their metadata documents
through the SSRF guard. `startExampleServer({ clients })` in `src/server.ts` takes other client
hosts and redirect URIs.

The end-to-end test runs on every commit, on Linux, macOS and Windows, over real sockets. It
serves a client's metadata document itself and drives the server with the official SDK client
(`@modelcontextprotocol/client`):

1. Discovery: an MCP request with no token gets the 401 challenge, which leads to the protected
   resource metadata and from there to the authorization server metadata.
2. Authorize with PKCE S256 and `state`; the demo sign-in; the consent page names the client and
   the host that vouches for it; approve (the form's CSRF token is checked).
3. The code and its verifier for tokens.
4. Tool calls through the SDK client, in both protocol eras the SDK serves (2026-07-28, and a
   2025-era client answered statelessly).
5. Refresh: a new access token and a new refresh token.
6. The rotated refresh token presented again: `invalid_grant`, and the whole family is revoked,
   so the successor is refused too and the connection is gone from `listGrants`.
7. The access token minted before the revocation keeps working until its lifetime (10 minutes
   by default) ends, then gets a 401 `invalid_token`: access tokens are not looked up, so revoking
   a family ends a connection at its next refresh.

The same file also covers `refreshTokenReuse: "refuse"` (the replay is refused and the successor
keeps working), the 403 step-up challenge for `add_note` with a read-only token, the SDK client's
own OAuth flow (discovery, the metadata document, PKCE, `state`, `iss`, and a refresh when the
access token expires), a denied consent, a forged CSRF token, a foreign `Host`, and the rate limiter.

One thing the test does differently from `npm start`: the SSRF guard refuses a loopback address
even when it comes from an injected resolver (the last test checks exactly that), so the test
reaches its own loopback document through `clientMetadata.unsafeFetchClientMetadata`, restricted to
its one client host.

## Experimental: fencing untrusted text

`mcp-frontdesk/experimental` exports `createFence()`, for a tool that returns text an outside party
wrote (an email, a web page, a ticket) to a model. It removes control characters and any copy of the
fence token, bounds the length, wraps the text in a labelled block, and gives you the instruction to
place beside it. The token is random per process by default. This cannot make a model ignore
instructions inside the text; nothing at the prompt level can. It only keeps the text from closing
its own block. The shape of this entry may change in a minor release.

## What it does not do

- No dynamic client registration and no `registration_endpoint`: clients use Client ID Metadata
  Documents (dynamic registration is deprecated in the MCP specification).
- No JWKS endpoint: tokens are verified by the server that minted them.
- No confidential clients, no `client_credentials`, no token introspection or revocation endpoint.
- No scope narrowing on refresh: a refresh may name the grant's scopes or fewer, but the new token
  always carries all of the grant's scopes (the response's `scope` says which). Naming a scope the
  grant does not hold is `invalid_scope`.
- No sign-in, sessions or consent UI.

The full list, with the RFCs and the specification version, is in [SPEC.md](SPEC.md).

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md). This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
