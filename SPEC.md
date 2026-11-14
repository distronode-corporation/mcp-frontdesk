# mcp-frontdesk v0.1.0: specification

What the code and tests implement. Reasons for the choices are in [DECISIONS.md](DECISIONS.md).

## Standards

| Document | Used for |
|---|---|
| MCP authorization specification, revision 2026-07-28 | The overall flow, canonical resource URIs, `resource` on every request, scope challenges, no tokens in query strings. |
| OAuth 2.1 (draft-ietf-oauth-v2-1) and RFC 6749 | Authorization code grant, refresh grant, error codes, no repeated parameters. |
| RFC 7636 | PKCE, S256 only. |
| draft-ietf-oauth-client-id-metadata-document | How a client is identified: an https `client_id` URL whose JSON document lists its name and redirect URIs. |
| RFC 8414 | Authorization server metadata. |
| RFC 9728 | Protected resource metadata, and `resource_metadata` in the challenge. |
| RFC 8707 | The `resource` parameter, compared with the configured resource. |
| RFC 9207 | `iss` on every authorization response. |
| RFC 9068 | The access-token format (`typ: at+jwt`). |
| RFC 6750 | Bearer usage and the `WWW-Authenticate` challenges. |
| RFC 8252 | Loopback redirects for native clients, any port. |

## Deliberately absent

- **Dynamic client registration** (RFC 7591), and so no `registration_endpoint`. The MCP
  specification deprecates it in favour of Client ID Metadata Documents.
- **A JWKS endpoint.** Access tokens are verified by the server that minted them; key rotation is
  handled by the key provider's `previous` keys.
- **Confidential clients.** Only `token_endpoint_auth_method: none`; a document declaring a secret
  or another method is refused, and so is a token request carrying `client_secret` or an
  `Authorization` header.
- **Other grants:** no implicit, password, `client_credentials` or device grant.
- **Token introspection (RFC 7662) and revocation (RFC 7009) endpoints.** Revocation is `revokeGrant`,
  called from the host's own settings page.
- **Pushed authorization requests, DPoP, mTLS.**

## Discovery

- Protected resource metadata at `/.well-known/oauth-protected-resource` plus the resource's path,
  and at the root form: `resource`, one `authorization_servers` entry (the issuer),
  `scopes_supported` (the resource scopes, never `offline_access`), `bearer_methods_supported:
  ["header"]`, and `resource_name` when configured.
- Authorization server metadata at `/.well-known/oauth-authorization-server` plus the issuer's path:
  `issuer`, both endpoints, `response_types_supported: ["code"]`, `grant_types_supported:
  ["authorization_code", "refresh_token"]`, `code_challenge_methods_supported: ["S256"]`,
  `token_endpoint_auth_methods_supported: ["none"]`, `client_id_metadata_document_supported: true`,
  `scopes_supported` (resource scopes plus `offline_access`),
  `authorization_response_iss_parameter_supported: true`.
- Served with `application/json`, `Cache-Control: public, max-age=3600` and
  `Access-Control-Allow-Origin: *`. HEAD and OPTIONS are answered; other methods get 405.

## Authorization request

Checked in this order. The first three failures are pages (`invalid_client`, `untrusted_client`,
`invalid_redirect`); every later one is a redirect with `error`, `state` (when valid) and `iss`.

1. `client_id` present once; its host on `clientIdHosts`; its URL canonical https on the default
   port, with a path, no userinfo, query or fragment, and a name host (not an IP literal); its
   document fetched and valid.
2. `redirect_uri` present once and registered in the document.
3. `response_type=code` (else `unsupported_response_type`); `code_challenge_method=S256` with a
   43-character challenge a SHA-256 digest can produce (its last character one of the 16 with no
   stray bits); `state` present and at most 512 characters; `resource` present (all
   `invalid_request`); `resource` exactly the configured resource, scheme and host
   case-insensitive, with no userinfo, query or fragment, not even an empty one (`invalid_target`); `scope`, when present, non-empty and made only of resource scopes and
   `offline_access` (`invalid_scope`).

Granted scopes: the resource scopes the request names, or `defaultScopes` when it names none (a
request for `offline_access` alone included). `approve` may narrow them, never widen.

## Client metadata document

- Fetched with `Accept: application/json`; 200 only; `application/json` or `application/*+json`; at
  most 5 KB; 5 seconds for the whole fetch, the DNS lookup included.
- Must be a JSON object whose `client_id` equals the URL; no `client_secret` or
  `client_secret_expires_at`; `token_endpoint_auth_method` absent or `none`; a `client_name` of 1 to
  80 characters after trimming with no control characters; 1 to 10 `redirect_uris`, every one on the
  allowlist (an exact configured URI, or canonical loopback when allowed).
- Good documents are cached per instance, at most 100, for `max-age` (default 5 minutes, at most an
  hour; `no-store`, `no-cache` and `private` are not cached). Refusals are never cached.

## Token endpoint

- POST, `application/x-www-form-urlencoded`, at most 8 KB, no repeated parameter, `client_id`
  required, no client credential. OPTIONS answers CORS for allowed origins; any other `Origin` gets
  403.
- Unknown `grant_type`: `unsupported_grant_type`; none: `invalid_request`.
- No signing key: `503 temporarily_unavailable`, before any code is spent or token rotated.
- `authorization_code`: `code`, `code_verifier`, `redirect_uri` required; `resource` absent or equal
  (`invalid_target`). Then the code is taken (spent), and the client, the exact redirect URI, the
  verifier and `isGrantActive` are checked. Any failure: `invalid_grant`.
- `refresh_token`: `refresh_token` required; `resource` absent or equal; `scope`, when present, made
  only of recognised scopes (`invalid_scope`, checked before rotation). The access token carries
  the grant's own scopes, narrowed to the scopes configured now.
- A scope removed from `scopes` since the grant (or the code) was made is dropped from what is
  minted and from the successor grant, and the response's `scope` lists what was granted (RFC 6749
  sections 3.3 and 6). A grant or code left with no scope: `invalid_grant`, and a grant's family is
  revoked.
- The signing key is fetched once per request, for the check above, and that key signs the access
  token. The access token is minted after every check and before the grant store is written. A mint
  that fails (a claims hook that throws) is a `500` that spends no refresh token and creates no
  grant. A code is spent before its checks, so on a failed exchange it is gone.
- The grant's `authorizedAt` is the time of consent, carried in the code, not the time of exchange.
- Success: `access_token`, `token_type: "Bearer"`, `expires_in`, `refresh_token`, `scope`, with
  `Cache-Control: no-store` and `Pragma: no-cache` (as on every answer, the CORS preflight included).
- A rate-limited request gets 429 with `Retry-After: 60` and `{"error":"slow_down"}`.
- An internal fault is `500 server_error`, reported.

## Access tokens

Header `alg: ES256`, `typ: at+jwt`, `kid`. Claims `iss`, `sub`, `aud` (one string), `iat`, `exp`
(`iat` plus the access lifetime), `jti`, `client_id`, `scope`, plus `accessTokenClaims`.
Verification requires all of them, allows 5 seconds of clock skew, refuses a token older than the
lifetime and an `iat` in the future, and refuses any scope the resource does not define.

## Gate

In order: an `Origin` not allowed is 403 `forbidden_origin`; a rate-limited request is 429, and a
rate limiter that throws is reported and answered 503 `temporarily_unavailable`; no
`Authorization` header is 401 `Bearer resource_metadata="<url>"`; an empty or malformed header, a request
path not in `resourcePaths`, or a token that does not verify is 401 with `error="invalid_token"`; a
token missing a required scope is 403 with `error="insufficient_scope"` and `scope="<all required>"`.

## Grants

A family starts at the code exchange. Each refresh claims the presented row and inserts its successor
atomically. Refusals: unknown, reused (family revoked under `"revoke-family"`), revoked, expired,
wrong client (family revoked), inactive (family revoked). A rotation that finds the family revoked
revokes it again, so no successor survives. Rotated rows are kept until their own expiry, because a
rotated row presented again is how reuse is detected.
