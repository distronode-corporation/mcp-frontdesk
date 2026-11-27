// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Which clients the authorization server talks to, and how redirect URIs are
 * matched. Pure functions over the configured allowlists.
 */

/** Loopback hosts for a native client (RFC 8252 section 7.3, plus `localhost`). */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "localhost", "[::1]"]);

function parse(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

/**
 * The host of an https client_id URL when that host is on the allowlist, else
 * null. Exact host names: a subdomain of an allowed host does not pass.
 */
export function trustedClientIdHost(clientId: string, allowedHosts: readonly string[]): string | null {
  const url = parse(clientId);
  if (!url || url.protocol !== "https:") return null;
  return allowedHosts.includes(url.hostname) ? url.hostname : null;
}

/** An `http://<loopback>` URI, the native-client redirect form. */
export function isLoopbackRedirect(raw: string): boolean {
  const url = parse(raw);
  return url !== null && url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
}

/**
 * May a client metadata document list this redirect URI? One of the configured
 * hosted URIs exactly, or (when loopback is allowed) a canonical
 * `http://<loopback>[:port]/<path>` with no userinfo and no fragment.
 */
export function isAllowedRedirectUri(raw: string, hosted: readonly string[], allowLoopback: boolean): boolean {
  if (hosted.includes(raw)) return true;
  if (!allowLoopback) return false;
  const url = parse(raw);
  return (
    url !== null &&
    url.href === raw &&
    isLoopbackRedirect(raw) &&
    url.username === "" &&
    url.password === "" &&
    !raw.includes("#")
  );
}

/**
 * Does the requested redirect_uri match one the client registered?
 *
 * Exact string equality, with one exception: a loopback registration matches a
 * request that differs from it only in the port (RFC 8252 section 7.3: a native
 * client binds an ephemeral port). Scheme, host, path and query must still be
 * identical, and the request must already be canonical, so `localhost` never
 * matches `127.0.0.1` and a path that merely normalises to the registered one
 * does not pass.
 */
export function matchesRegisteredRedirect(requested: string, registered: readonly string[]): boolean {
  if (registered.includes(requested)) return true;
  const req = parse(requested);
  if (!req || req.href !== requested || !isLoopbackRedirect(requested) || requested.includes("#")) return false;
  return registered.some((entry) => {
    const reg = parse(entry);
    return (
      reg !== null &&
      isLoopbackRedirect(entry) &&
      reg.hostname === req.hostname &&
      reg.pathname === req.pathname &&
      reg.search === req.search &&
      reg.username === req.username &&
      reg.password === req.password
    );
  });
}
