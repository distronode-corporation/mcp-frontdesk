# Security model

`mcp-frontdesk` decides who may call an MCP server and with what. This document says what it
protects, what it trusts, and where its guarantees stop. The protocol details are in [SPEC.md](SPEC.md).

## Assets

- **People's accounts on your server**, reachable through an access token.
- **Refresh tokens**, which mint access tokens for up to the refresh lifetime (30 days by default,
  sliding), and never past the family's absolute lifetime (`maxFamilyLifetimeSeconds`, 30 days
  from the first sign-in by default).
- **The signing key.** Whoever holds it can mint access tokens for anyone.
- **Your server's network position.** The client metadata fetch is an outbound request whose URL a
  stranger chooses.

## Threat model

Who can do what, and which part of this package stands in their way:

| Actor | What they can do | What stops them |
|---|---|---|
| Anyone on the network | Send any request to every endpoint, any number of times. | Every input is checked before use; the token endpoint never says why it refused; a `rateLimiter` if the host passes one. |
| A malicious MCP client | Pick any `client_id` URL, any redirect URI, any scopes and parameters. | Only configured client hosts are fetched; every redirect URI must be on the host's allowlist; PKCE S256 is mandatory. |
| A malicious client metadata document | Point at internal addresses, redirect, stall, grow without end, or claim another client's name. | The SSRF guard, the pinned GET, the deadline and the 5 KB cap; `clientName` is always shown beside the host that vouches for it. |
| A thief of a code or a refresh token | Present it, once or many times, from another client. | Codes are single use and bound to the client, the redirect and the PKCE challenge; a replay revokes what the code issued; refresh tokens rotate and a reuse revokes the family. |
| A thief of an access token | Call the MCP server until it expires. | One audience, `resourcePaths`, a short lifetime (10 minutes by default) and a maximum age whatever `exp` says. |

Out of scope: a compromised host application, config, store or signing key, which are trusted
(below), and everything listed under [What it does not protect](#what-it-does-not-protect).

## Trust boundaries

| Party | Trusted? | Why |
|---|---|---|
| The host application (your code) | **Yes** | It signs people in, shows consent, calls `approve`, implements the stores and the key provider. |
| The config | **Yes** | It decides which client hosts and redirect URIs exist at all. |
| The person at the consent page | Yes, for their own account | Their "yes" is what `approve` records. |
| MCP clients | **No** | A client is identified by a URL on an allowed host; its document is self-asserted, so `clientName` is shown beside the host, never instead of it. |
| Client metadata documents | **No** | Fetched behind the SSRF guard, capped, and validated field by field. Every redirect URI they list must be on your allowlist. |
| Anyone on the network | **No** | They can send any request to every endpoint. |

## What each control guarantees

- **Codes** are 256-bit random values, stored as SHA-256 hashes for 60 seconds by default, bound to
  the client, the exact redirect URI, the PKCE challenge, the subject, the scopes, the context and
  the time of consent. They are spent once the token endpoint takes them from the store, even if a
  later check fails. A request refused before that (a missing field, another `resource`, a verifier
  too malformed to ever match, no signing key) leaves the code unspent.
- **A replayed code revokes what it issued** (RFC 6749 section 4.1.2). Taking a code leaves a
  tombstone, for the code's lifetime plus 10 minutes, naming the family its redemption starts. A
  later presentation of the code, by anyone, with any verifier, revokes that family and is answered
  with the same `invalid_grant`. A replay that lands while the first redemption is still running
  flags the tombstone; the first redemption checks the flag after it writes the grant, and then
  revokes that grant and refuses too, so no token leaves. Either way the family's refresh tokens die
  at once. Access tokens are not looked up: one the first redemption already handed out lives out
  its lifetime (10 minutes by default).
- **PKCE S256 is mandatory.** `plain` is refused, and the challenge must be 43 base64url characters.
- **Redirects are exact**, with one exception from RFC 8252: a loopback registration matches any
  port. An error is redirected only after the client and its redirect URI are verified; before that
  the host shows a page (no open redirect).
- **`iss` is on every authorization response**, errors included (RFC 9207), so a client can detect a
  mix-up between authorization servers.
- **Access tokens** are ES256 JWTs with `typ: at+jwt`, exactly one audience (the resource), a kid
  that must name a key the provider accepts, and a maximum age equal to the configured lifetime
  whatever their `exp` says. They are valid only on `resourcePaths`.
- **Refresh tokens** rotate on every use, are bound to their client, and are stored as hashes.
- **A family has an absolute lifetime.** Refreshing slides each token's expiry, but never past
  `maxFamilyLifetimeSeconds` after the family's first sign-in (`familyCreatedAt`). A refresh at or
  after that end is refused and revokes the family, so even an undetected copy of a refresh token
  stops working by then.
- **The token endpoint never says why.** Every refusal of a code or a grant is `invalid_grant`.
  The one other answer a token can earn is `invalid_scope`, on a refresh that names a scope the
  grant does not hold, and it is decided last: after the token was found, and found unrotated,
  unrevoked, unexpired, within its family's lifetime, bound to this client and still active. A
  dead token gets `invalid_grant` whatever scope it names, so `invalid_scope` tells only the holder
  of a live token what a successful refresh would tell them anyway. Such a refusal does not rotate
  the token, so the holder learns the token is live without spending it; they could use it anyway,
  so this gives no access they did not have. A scope this server does not recognise at all is
  `invalid_scope` before the token is looked up, which depends on nothing about the token.

## Refresh-token reuse: the trade-off

A rotated refresh token presented again means one of two things: an attacker copied it, or the
legitimate client lost the response to its last refresh and retried.

- `"revoke-family"` (the default) treats every reuse as theft. The attacker's copy and the client's
  current token both die, and the person reconnects. A flaky network can sign someone out.
- `"refuse"` refuses only the reused token. A retried refresh costs nothing, but an attacker who
  refreshes before the client does keeps a live token, and the client is the one refused. The
  client's later attempts are reuse, which this mode only refuses, so the thief can keep refreshing
  until the family's absolute lifetime (`maxFamilyLifetimeSeconds` from the first sign-in), unless
  the family is revoked before that or goes `ttl.refreshToken` without a refresh. The last access
  token minted works for up to `ttl.accessToken` after that.

Choose `"refuse"` only if your clients retry refreshes and you accept that. In both modes, the
current refresh token of a family (the newest, not yet replaced by a refresh), presented by a client
other than the one it was issued to, revokes the family. A token that a refresh has already replaced
is reuse first, so under `"refuse"` it is only refused, whoever presents it.

## What it does not protect

- **Your consent page.** CSRF protection on the approve action, the sign-in itself, and making sure
  the page shows the client host and redirect host are yours. `approve` must be called only from a
  deliberate action by the signed-in person, never on a page load.
- **Rate limits,** unless you pass a `rateLimiter`. See the README's table.
- **Access tokens already minted.** Revoking a grant stops the next refresh; an access token lives
  out its lifetime (10 minutes by default). Check what must take effect at once (a removed tenant
  membership, say) in your own handler as well.
- **The stores.** If your store's `take` or `rotate` is not atomic, replay detection fails, and a
  `take` that does not leave its tombstone in the same step, or a `markReplayed` that is not atomic,
  lets a replayed code revoke nothing. A grant store that drops `familyCreatedAt` breaks the
  absolute lifetime. Run the contract suite in `mcp-frontdesk/testing`.
- **The key.** Keep it in a secret store. Rotating it costs each connected client one refresh: sign
  with the new key and pass the old public key as `previous` for one access-token lifetime.
- **The unsafe fetch option.** `clientMetadata.unsafeFetchClientMetadata` turns the SSRF guard off.
- **Prompt injection.** The experimental fencing helpers narrow it; they cannot prevent it.

## Secure design principles applied

- **Least privilege.** A token carries the scopes the person approved and no more, one audience,
  and only the `resourcePaths` it may be used on (`access-token.ts`, `gate.ts`). No email or other
  personal data goes into a token unless the host adds it. Stores see hashes, never codes or
  refresh tokens (`encoding.ts`, `stores.ts`).
- **Fail closed.** A store, key provider, rate limiter or hook that throws is a refusal,
  never a token or a code (`token-endpoint.ts`, `authorize.ts`; tests under "hooks that fail never
  change an answer" in `test/token-endpoint.test.ts`). A config that cannot work, or a code store
  without the tombstone, is refused at `createFrontdesk` (`config.ts`).
- **Complete mediation.** `approve` checks the whole authorization request again instead of
  trusting the consent page's earlier check. Every refresh asks `isGrantActive`, and every MCP
  request goes through `authenticate`, which checks the signature and every claim.
- **Economy of mechanism.** One runtime dependency (`jose`), one algorithm (ES256), public
  clients only, no dynamic registration, JWKS, introspection or extra grants
  ([SPEC.md](SPEC.md#deliberately-absent)). The config and request checks are small hand-written
  functions rather than a schema library ([DECISIONS.md](DECISIONS.md#dependencies)).
- **Safe defaults.** The secure choice is the default: the SSRF guard on, refresh reuse revokes
  the family, loopback redirects off, no product presets unless spread in.

## Common weaknesses countered

Mapped to the CWE Top 25 and the OWASP Top 10. Each line names the mechanism and the tests that pin it.

| Weakness | How it is countered | Tests |
|---|---|---|
| Server-side request forgery (CWE-918, OWASP A10) | `ssrf.ts` refuses internal names and every private, loopback, link-local, shared and reserved range (IPv6 forms that embed one included); `pinned-get.ts` connects only to the checked addresses and follows no redirect. | `test/ssrf.test.ts`, `test/pinned-get.test.ts`, `test/client-metadata.test.ts` |
| Improper input validation (CWE-20) | The config is checked once by `resolveConfig`; authorization and token requests are checked parameter by parameter, a repeated parameter is refused, and a client metadata document is validated field by field. | `test/config-discovery.test.ts`, `test/authorize.test.ts`, `test/token-endpoint.test.ts`, `test/client-metadata.test.ts` |
| Uncontrolled resource consumption (CWE-400) | Streaming caps on the token request (8 KB) and the metadata document (5 KB); one 5 second deadline on the metadata fetch. | `test/primitives.test.ts` (readCapped), `test/client-metadata.test.ts` |
| Open redirect (CWE-601) | No redirect until the client and its exact redirect URI are verified; before that the host shows a page. | `test/authorize.test.ts` ("client and redirect failures are pages, never redirects") |
| Improper authentication and token misuse (CWE-287, CWE-294, OWASP A07) | PKCE S256 only; single-use codes with replay revocation; refresh rotation with reuse detection; access tokens verified with the algorithm, `typ`, kid, issuer, one audience and a maximum age pinned. | `test/token-endpoint.test.ts`, `test/tokens.test.ts`, `test/gate.test.ts` |
| Information exposure (CWE-200, CWE-209) | Every refusal of a code or a refresh token is the same `invalid_grant`, the gate does not say which check failed, and reasons go only to the audit sink. | `test/token-endpoint.test.ts`, `test/gate.test.ts` |
| Storage of secrets in the clear (CWE-312) | Codes and refresh tokens are stored as SHA-256 hashes; the audit events carry ids and reasons, never a code or a token (`config.ts`, `AuditEvent`). | |
| Insufficient randomness (CWE-330) | Codes and refresh tokens are 256 bits from `crypto.randomBytes` (`encoding.ts`). | `test/primitives.test.ts` |
| Deserialization of untrusted data (CWE-502) | The only parsed input is JSON (`JSON.parse`, no revivers or class instantiation) and form bodies, both checked field by field before use. | `test/client-metadata.test.ts`, `test/token-endpoint.test.ts` |
| Race conditions on single-use values (CWE-362) | `CodeStore.take` and `GrantStore.rotate` must be atomic, and the contract suite fires concurrent calls to prove it. | `test/stores.test.ts` |
| Injection (CWE-74, CWE-79, OWASP A03) | No SQL, shell or HTML is built here: storage is the host's, and responses are JSON or fixed challenge headers built from the host's own config values. | |
| Path traversal (CWE-22) | Not applicable: the package reads and writes no files. | |

## Reporting

See [SECURITY.md](SECURITY.md).
