# Architecture

How mcp-frontdesk is put together: the parts, how a request moves through them, and where state
lives. What each endpoint does on the wire is in [SPEC.md](SPEC.md), why it was built this way is in
[DECISIONS.md](DECISIONS.md), and what it trusts is in [SECURITY-MODEL.md](SECURITY-MODEL.md).

## The shape

mcp-frontdesk is a library, not a server. `createFrontdesk(config)` checks the config once and
returns an object of handlers. Each handler takes a Web `Request` (or the authorization request's
parameters) and returns a `Response` (or a result the host turns into one). The host owns
everything around it: the HTTP server, routing, sign-in, the consent page, storage and the signing
key.

```
                 MCP client                          the person
                     |                                   |
                     v                                   v
  +------------------------------------------------------------------------+
  | host application (your code): HTTP server, routing, sign-in, consent   |
  +------------------------------------------------------------------------+
     |  handleDiscovery   |  checkAuthorizeRequest   |  handleToken    |  authenticate
     |                    |  approve, denialUrl      |                 |
     v                    v                          v                 v
  discovery.ts        authorize.ts              token-endpoint.ts   gate.ts
                          |                       |        |           |
                          v                       v        v           v
                  client-metadata.ts         grants.ts   access-token.ts (jose, ES256)
                   ssrf.ts, pinned-get.ts         |        ^
                          |                       v        |
                    outbound HTTPS          host adapters: CodeStore, GrantStore, KeyProvider,
                    (client_id URL)         and the optional hooks (rateLimiter, audit, ...)
```

## Parts

| Module | Role |
|---|---|
| `frontdesk.ts` | `createFrontdesk`: wires the parts below into one object. |
| `config.ts` | The one config object, checked by `resolveConfig`; a config that cannot work throws `FrontdeskConfigError` at startup. |
| `context.ts` | What every part shares: the checked config, the host's adapters, and wrappers that make `reporter` and `audit` never throw. |
| `discovery.ts` | The RFC 9728 and RFC 8414 documents. |
| `authorize.ts` | The authorization request, checked in a fixed order, and `approve`, which checks again and mints a code. |
| `client-metadata.ts`, `client-policy.ts` | Client ID Metadata Documents: fetched, cached, validated field by field, and matched against the configured hosts and redirect URIs. |
| `ssrf.ts`, `pinned-get.ts` | The SSRF guard and the one HTTPS GET it allows, connected only to the addresses the guard checked. |
| `token-endpoint.ts` | The token endpoint: `authorization_code` with PKCE, `refresh_token` with rotation. |
| `grants.ts` | Refresh-token families over the host's `GrantStore`: rotation, reuse detection, the absolute lifetime. |
| `access-token.ts`, `keys.ts` | Minting and verifying ES256 access tokens; reading and generating keys. |
| `gate.ts` | The bearer gate and its 401 and 403 challenges. |
| `pkce.ts`, `encoding.ts`, `read-capped.ts` | Small shared pieces: PKCE S256, random values and hashes, the streaming body cap. |
| `stores.ts`, `memory-stores.ts`, `testing.ts` | The store interfaces, the in-memory stores, and the contract suite (`mcp-frontdesk/testing`). |
| `experimental.ts` | `createFence` (`mcp-frontdesk/experimental`), separate from the authorization path. |

## A connection, start to finish

1. **Discovery.** An MCP request without a token reaches `authenticate`, which answers 401 with
   `resource_metadata`. The client reads the protected resource metadata and then the
   authorization server metadata from `handleDiscovery`.
2. **Authorization.** The host's consent route calls `checkAuthorizeRequest`. It checks the
   `client_id` host against the config, fetches the client's metadata document through the SSRF
   guard, checks the redirect URI, then PKCE, scopes and `resource`. The host signs the person in
   and shows the consent page. On "yes" it calls `approve`, which runs every check again and
   stores a code (as a SHA-256 hash) in the `CodeStore`.
3. **Code exchange.** `handleToken` reads the form body under a cap, takes the code from the
   `CodeStore` atomically, checks the client, the redirect URI and the PKCE verifier, mints an
   access token, and writes the first refresh token of a new family to the `GrantStore`.
4. **Calls.** Each MCP request carries the access token. `authenticate` verifies the signature and
   every claim, without any store lookup, and hands the host the subject, client and scopes.
5. **Refresh.** `handleToken` finds the refresh token's row by hash, checks it, mints a new access
   token, and rotates the row to a successor in the same family as one store operation.
6. **Revocation.** `revokeGrant` (from the host's settings page), a reused refresh token or a
   replayed code revokes the family. Its refresh tokens stop at once; access tokens already minted
   live out their lifetime.

## Where state lives

mcp-frontdesk keeps no state of its own beyond a cache of good client metadata documents in
memory. Everything that must survive a request is in the host's adapters:

- **`CodeStore`**: authorization codes and the tombstones of spent ones, by hash.
- **`GrantStore`**: refresh-token rows, by hash, grouped in families.
- **`KeyProvider`**: the signing key and any previous public keys.

Codes and refresh tokens are never stored in the clear, and access tokens are not stored at all.
The in-memory stores in the package are for one process; a host running more than one runs its
own stores against the contract suite.

## Trust boundaries

The host and its config are trusted; MCP clients, their metadata documents and the network are
not. The full table, and what each control guarantees, is in
[SECURITY-MODEL.md](SECURITY-MODEL.md#trust-boundaries).
