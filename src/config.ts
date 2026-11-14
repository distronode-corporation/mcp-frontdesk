/**
 * The one configuration object, checked once by `createFrontdesk`. There are
 * no product defaults: the URLs, scopes, client hosts and redirect URIs are
 * the host's. Only the lifetimes have defaults, and they are security
 * parameters (see SPEC.md).
 */
import type { HostResolver } from "./ssrf.ts";
import type { KeyProvider } from "./keys.ts";
import type { CodeStore, GrantContext, GrantStore } from "./stores.ts";

/** What a grant is, as the hooks see it. */
export interface GrantInfo {
  subject: string;
  clientId: string;
  scopes: readonly string[];
  context: GrantContext;
  /** Null at the code exchange, before the family exists. */
  familyId: string | null;
  authorizedAt: Date;
}

/** The endpoints a RateLimiter is asked about. */
export type RateLimitedEndpoint = "token" | "resource";

export interface RateLimiter {
  /** True to let the request through. The host decides the key (client IP, for example). */
  allow(endpoint: RateLimitedEndpoint, request: Request): boolean | Promise<boolean>;
}

export interface Reporter {
  /** An internal fault: a store or key failure, a hook that threw. Must not throw. */
  error(where: string, err: unknown): void;
}

export type AuditEvent =
  | { type: "code.issued"; subject: string; clientId: string; scopes: readonly string[] }
  | { type: "grant.created"; subject: string; clientId: string; familyId: string; scopes: readonly string[] }
  | { type: "grant.refreshed"; subject: string; clientId: string; familyId: string }
  | {
      type: "grant.revoked";
      subject: string;
      clientId: string;
      familyId: string;
      reason: "reuse" | "client_mismatch" | "inactive" | "user";
    }
  | { type: "token.refused"; grantType: "authorization_code" | "refresh_token"; reason: string };

export interface AuditSink {
  /** Called in order. A sink that throws is reported, and never changes an answer. */
  record(event: AuditEvent): void | Promise<void>;
}

/**
 * Routes codes and refresh tokens, for a host that runs more than one
 * deployment: `wrap` decorates a value before it is handed out (with a routing
 * label a load balancer can read, say), `unwrap` returns the bare value or null
 * for one this deployment should not look up. Only the bare value is hashed
 * and stored.
 */
export interface TokenWrapper {
  wrap(kind: "code" | "refresh_token", value: string): string;
  unwrap(kind: "code" | "refresh_token", presented: string): string | null;
}

/** What to do when a refresh token that was already rotated is presented again. */
export type RefreshTokenReusePolicy = "revoke-family" | "refuse";

export interface FrontdeskConfig {
  /** The authorization server's issuer identifier (RFC 8414): https, no query or fragment. */
  issuer: string;
  /** The MCP server's canonical URI (RFC 8707, RFC 9728). Every token's audience. */
  resource: string;
  /** Request paths an access token may be used on. Defaults to the resource URL's path. */
  resourcePaths?: readonly string[];
  /** `resource_name` in the protected resource metadata. */
  resourceName?: string;
  /** The resource's scopes. `offline_access` is recognised in requests and never listed here. */
  scopes: readonly string[];
  /** Granted when a request names none of `scopes`. Defaults to all of `scopes`. */
  defaultScopes?: readonly string[];
  /** The consent page, as a path under the issuer's origin or an absolute URL. */
  authorizationEndpoint: string;
  /** The token endpoint, as a path under the issuer's origin or an absolute URL. */
  tokenEndpoint: string;
  /** Hosts whose Client ID Metadata Documents are accepted, exact names. */
  clientIdHosts: readonly string[];
  /** Exact redirect URIs a client document may list (hosted callbacks). */
  redirectUris: readonly string[];
  /** Also accept `http://localhost`, `127.0.0.1` and `[::1]` redirects, any port (RFC 8252). Default false. */
  allowLoopbackRedirects?: boolean;
  /**
   * Origins allowed to call the token endpoint and the resource from a browser.
   * A request carrying any other `Origin` is refused (MCP's DNS-rebinding rule).
   * Requests without an `Origin` header (server-side clients) are unaffected.
   */
  allowedOrigins: readonly string[];
  /** Lifetimes in seconds. */
  ttl?: { authorizationCode?: number; accessToken?: number; refreshToken?: number };
  keys: KeyProvider;
  codeStore: CodeStore;
  grantStore: GrantStore;
  rateLimiter?: RateLimiter;
  reporter?: Reporter;
  audit?: AuditSink;
  /** Default "revoke-family". See SECURITY-MODEL.md for the trade-off. */
  refreshTokenReuse?: RefreshTokenReusePolicy;
  /**
   * Extra access-token claims (an email, a tenant id). Registered claims
   * (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, `client_id`)
   * cannot be set here.
   */
  accessTokenClaims?: (grant: GrantInfo) => Record<string, unknown> | Promise<Record<string, unknown>>;
  /**
   * Is this grant still allowed? Asked at the code exchange and at every
   * refresh, before anything is minted (has the person left the tenant, reset
   * their password since `authorizedAt`?). False refuses with `invalid_grant`
   * and, on a refresh, revokes the family.
   */
  isGrantActive?: (grant: GrantInfo) => boolean | Promise<boolean>;
  tokenWrapper?: TokenWrapper;
  /** How client metadata documents are fetched. */
  clientMetadata?: {
    /** Replaces the system resolver (the SSRF guard still checks every address). */
    resolveHost?: HostResolver;
    /**
     * Replaces the guarded fetch entirely. The SSRF guard does NOT run: use it
     * only where every client_id host is trusted, or in tests. The deadline,
     * the 5 KB cap and every document check still apply.
     */
    unsafeFetchClientMetadata?: (url: string, init: { signal: AbortSignal }) => Promise<Response>;
  };
  /** Clock in milliseconds. Defaults to `Date.now`. */
  now?: () => number;
}

export interface ResolvedConfig {
  issuer: string;
  resource: string;
  resourcePaths: readonly string[];
  resourceName: string | undefined;
  scopes: readonly string[];
  defaultScopes: readonly string[];
  /** `scopes` plus `offline_access`: what a request may name without `invalid_scope`. */
  requestableScopes: readonly string[];
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientIdHosts: readonly string[];
  redirectUris: readonly string[];
  allowLoopbackRedirects: boolean;
  allowedOrigins: readonly string[];
  codeTtlSeconds: number;
  accessTtlSeconds: number;
  refreshTtlSeconds: number;
  refreshTokenReuse: RefreshTokenReusePolicy;
  now: () => number;
}

export const OFFLINE_ACCESS = "offline_access";

/** Default lifetimes, in seconds. */
export const DEFAULT_TTL = { authorizationCode: 60, accessToken: 600, refreshToken: 30 * 24 * 60 * 60 } as const;

/** RFC 6749 section 3.3 scope-token. */
const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/;

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class FrontdeskConfigError extends Error {
  constructor(message: string) {
    super(`mcp-frontdesk config: ${message}`);
    this.name = "FrontdeskConfigError";
  }
}

function fail(message: string): never {
  throw new FrontdeskConfigError(message);
}

/** https, or http on a loopback host (for local development). */
function secureOrLoopback(url: URL): boolean {
  return url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname));
}

function parseUrl(name: string, raw: unknown): URL {
  if (typeof raw !== "string") fail(`${name} must be a string`);
  try {
    return new URL(raw);
  } catch {
    return fail(`${name} is not a URL`);
  }
}

/** A URL in its canonical form: no trailing slash on an empty path, no query, no fragment. */
export function canonicalUrl(url: URL): string {
  return url.pathname === "/" ? url.origin : `${url.origin}${url.pathname}`;
}

function checkIdentifier(name: string, raw: unknown): string {
  const url = parseUrl(name, raw);
  if (!secureOrLoopback(url)) fail(`${name} must be https (http only on a loopback host)`);
  // The canonical form drops userinfo, query and fragment, so one comparison refuses all of them.
  if (canonicalUrl(url) !== raw) {
    fail(`${name} must be canonical: lower-case scheme and host, no trailing slash, no userinfo, query or fragment`);
  }
  return raw as string;
}

function stringList(name: string, raw: unknown, allowEmpty: boolean): string[] {
  if (!Array.isArray(raw) || !raw.every((entry) => typeof entry === "string" && entry !== "")) {
    fail(`${name} must be an array of non-empty strings`);
  }
  if (!allowEmpty && raw.length === 0) fail(`${name} must not be empty`);
  return [...(raw as string[])];
}

function endpoint(name: string, raw: unknown, issuer: string): string {
  if (typeof raw !== "string" || raw === "") fail(`${name} must be a path or a URL`);
  const url = raw.startsWith("/") ? new URL(raw, new URL(issuer).origin) : parseUrl(name, raw);
  if (!secureOrLoopback(url)) fail(`${name} must be https (http only on a loopback host)`);
  return url.href;
}

function ttl(name: string, raw: number | undefined, fallback: number): number {
  const value = raw ?? fallback;
  if (!Number.isInteger(value) || value <= 0) fail(`ttl.${name} must be a positive integer number of seconds`);
  return value;
}

export function resolveConfig(config: FrontdeskConfig): ResolvedConfig {
  if (typeof config !== "object" || config === null) fail("a config object is required");
  const issuer = checkIdentifier("issuer", config.issuer);
  const resource = checkIdentifier("resource", config.resource);

  const scopes = stringList("scopes", config.scopes, false);
  for (const scope of scopes) {
    if (!SCOPE_TOKEN.test(scope)) fail(`scope "${scope}" is not a valid scope token`);
    if (scope === OFFLINE_ACCESS) fail(`"${OFFLINE_ACCESS}" is not a resource scope; it is recognised without being listed`);
  }
  const defaultScopes = config.defaultScopes === undefined ? scopes : stringList("defaultScopes", config.defaultScopes, false);
  if (defaultScopes.some((scope) => !scopes.includes(scope))) fail("defaultScopes must be a subset of scopes");

  const resourcePaths =
    config.resourcePaths === undefined ? [new URL(resource).pathname] : stringList("resourcePaths", config.resourcePaths, false);
  if (resourcePaths.some((path) => !path.startsWith("/"))) fail("resourcePaths must be absolute paths");

  const clientIdHosts = stringList("clientIdHosts", config.clientIdHosts, false);
  const redirectUris = stringList("redirectUris", config.redirectUris, true);
  for (const uri of redirectUris) {
    const url = parseUrl("redirectUris entry", uri);
    if (url.protocol !== "https:" || url.href !== uri || uri.includes("#")) {
      fail(`redirect URI ${uri} must be a canonical https URL with no fragment`);
    }
  }
  const allowLoopbackRedirects = config.allowLoopbackRedirects ?? false;
  if (redirectUris.length === 0 && !allowLoopbackRedirects) fail("no redirect URI could ever be accepted");
  const allowedOrigins = stringList("allowedOrigins", config.allowedOrigins, true);
  for (const origin of allowedOrigins) {
    if (parseUrl("allowedOrigins entry", origin).origin !== origin) fail(`allowed origin ${origin} must be an origin`);
  }

  if (config.refreshTokenReuse !== undefined && config.refreshTokenReuse !== "revoke-family" && config.refreshTokenReuse !== "refuse") {
    fail('refreshTokenReuse must be "revoke-family" or "refuse"');
  }
  for (const [name, value] of [
    ["keys", config.keys],
    ["codeStore", config.codeStore],
    ["grantStore", config.grantStore],
  ] as const) {
    if (typeof value !== "object" || value === null) fail(`${name} is required`);
  }

  return {
    issuer,
    resource,
    resourcePaths,
    resourceName: config.resourceName,
    scopes,
    defaultScopes,
    requestableScopes: [...scopes, OFFLINE_ACCESS],
    authorizationEndpoint: endpoint("authorizationEndpoint", config.authorizationEndpoint, issuer),
    tokenEndpoint: endpoint("tokenEndpoint", config.tokenEndpoint, issuer),
    clientIdHosts,
    redirectUris,
    allowLoopbackRedirects,
    allowedOrigins,
    codeTtlSeconds: ttl("authorizationCode", config.ttl?.authorizationCode, DEFAULT_TTL.authorizationCode),
    accessTtlSeconds: ttl("accessToken", config.ttl?.accessToken, DEFAULT_TTL.accessToken),
    refreshTtlSeconds: ttl("refreshToken", config.ttl?.refreshToken, DEFAULT_TTL.refreshToken),
    refreshTokenReuse: config.refreshTokenReuse ?? "revoke-family",
    now: config.now ?? Date.now,
  };
}

/**
 * Claude's client hosts and hosted callbacks, as a named preset. Spread it into
 * the config: `createFrontdesk({ ...claudeClients, issuer, ... })`. Nothing is
 * accepted from Claude unless the host does so.
 *
 * - `claude.ai` hosts the client metadata documents of Claude's apps and of
 *   Claude Code; `claude.com` is admitted for a move of the hosted callback.
 * - The hosted apps call back to `/api/mcp/auth_callback` on either host.
 * - Claude Code is a native client: it uses a loopback redirect with an
 *   ephemeral port.
 */
export const claudeClients = Object.freeze({
  clientIdHosts: Object.freeze(["claude.ai", "claude.com"]),
  redirectUris: Object.freeze(["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"]),
  allowLoopbackRedirects: true,
});
