# Roadmap

The near-term plan for mcp-frontdesk, and what it will not do. The repository has no open issues
today, so the plan is taken from what its own documents say is not settled yet: the README's
status note and its "Experimental" and "What it does not do" sections, and
[DECISIONS.md](DECISIONS.md). It has no dates: an item is done when the change that does it is
merged and released, and it then leaves this list for [CHANGELOG.md](CHANGELOG.md). Anything here
can change; open an [issue](https://github.com/distronode-corporation/mcp-frontdesk/issues) to
discuss an item or to propose a new one.

## Near term

- **Toward 1.0.** The package is at 0.1.0, and the README says the API may still change before
  1.0. Until then, under [Semantic Versioning](https://semver.org/), a minor release may change
  the API, and the CHANGELOG lists every change. 1.0 is the release after which
  the API changes only in a major version.
- **The experimental fence.** `createFence()` in `mcp-frontdesk/experimental` may change shape in
  a minor release (README, "Experimental: fencing untrusted text"). It stays under that entry
  point until its shape is settled.
- **The next release.** What is merged under "Unreleased" in the CHANGELOG goes out in the next
  version.

## Not planned

These are decisions, listed in the README's "What it does not do", in [SPEC.md](SPEC.md) and in
DECISIONS.md, "Not carried over from the original":

- No dynamic client registration and no `registration_endpoint`: clients use Client ID Metadata
  Documents, and dynamic registration is deprecated in the MCP specification.
- No JWKS endpoint: tokens are verified by the server that minted them.
- No confidential clients, no `client_credentials` grant, and no token introspection or
  revocation endpoint.
- No sign-in, sessions or consent UI: those belong to the host application.
- No storage backend beyond the in-memory stores: a host brings its own behind the two store
  interfaces, checked by the contract suite in `mcp-frontdesk/testing`.
- No product rules (account and tenant checks, feature flags on scopes) and no logging or error
  reporting integrations: the host adds them through `isGrantActive`, `reporter` and `audit`.

A change to any of these would be proposed as an issue first, since each one changes what
[SECURITY-MODEL.md](SECURITY-MODEL.md) describes or the package's small surface.
