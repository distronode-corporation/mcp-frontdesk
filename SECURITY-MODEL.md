# Security model

`mcp-frontdesk` decides who may call an MCP server and with what. This document says what it
protects, what it trusts, and where its guarantees stop. The protocol details are in [SPEC.md](SPEC.md).

## Assets

- **People's accounts on your server**, reachable through an access token.
- **Refresh tokens**, which mint access tokens for up to the refresh lifetime (30 days by default,
  sliding).
- **The signing key.** Whoever holds it can mint access tokens for anyone.
- **Your server's network position.** The client metadata fetch is an outbound request whose URL a
  stranger chooses.

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
- **The token endpoint never says why.** Every refusal of a code or a grant is `invalid_grant`.

## Refresh-token reuse: the trade-off

A rotated refresh token presented again means one of two things: an attacker copied it, or the
legitimate client lost the response to its last refresh and retried.

- `"revoke-family"` (the default) treats every reuse as theft. The attacker's copy and the client's
  current token both die, and the person reconnects. A flaky network can sign someone out.
- `"refuse"` refuses only the reused token. A retried refresh costs nothing, but an attacker who
  refreshes before the client does keeps a live token, and the client is the one refused.

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
- **The stores.** If your store's `take` or `rotate` is not atomic, replay detection fails. Run the
  contract suite in `mcp-frontdesk/testing`.
- **The key.** Keep it in a secret store. Rotating it costs each connected client one refresh: sign
  with the new key and pass the old public key as `previous` for one access-token lifetime.
- **The unsafe fetch option.** `clientMetadata.unsafeFetchClientMetadata` turns the SSRF guard off.
- **Prompt injection.** The experimental fencing helpers narrow it; they cannot prevent it.

## Reporting

See [SECURITY.md](SECURITY.md).
