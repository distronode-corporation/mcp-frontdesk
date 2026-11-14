/**
 * The authorization request (RFC 6749 section 4.1.1 with PKCE, RFC 8707 and
 * RFC 9207), checked in one fixed order, and the approval that mints a code.
 *
 * The order decides whether an error may be redirected. While the client or
 * its redirect_uri is unverified, the server must not redirect (that would be
 * an open redirect), so those failures are for the host to show as a page.
 * Once both are verified, every later failure goes back to the client as
 * `?error=...&state=...&iss=...`:
 *   1. client_id: present once, its host allowed, its metadata document
 *      fetched and valid;
 *   2. redirect_uri: present once and registered in that document;
 *   3. response_type `code`; PKCE S256 with a well-formed challenge; `state`
 *      (required: it is the client's CSRF defence); `resource` exactly this
 *      resource; `scope` made only of scopes this server recognises.
 *
 * `iss` is on every redirect, errors included (RFC 9207 section 2).
 *
 * No session is read here. The host checks the request first and its own
 * session second, so nothing about a signed-in user is touched for a request
 * that names an untrusted client.
 */
import { canonicalUrl } from "./config.ts";
import type { Context } from "./context.ts";
import { trustedClientIdHost, isLoopbackRedirect, matchesRegisteredRedirect } from "./client-policy.ts";
import { randomToken, sha256Hex } from "./encoding.ts";
import { isValidCodeChallenge } from "./pkce.ts";
import type { GrantContext } from "./stores.ts";

/** The longest `state` echoed back. */
export const STATE_MAX_LENGTH = 512;

/** The parameters of an authorization request. */
export const AUTHORIZE_PARAMS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "code_challenge",
  "code_challenge_method",
  "state",
  "resource",
  "scope",
] as const;

/**
 * The raw parameters: a string, an array when repeated, or absent. RFC 6749
 * section 3.1: a parameter must not repeat, so an array is always a refusal.
 */
export type RawAuthorizeParams = Partial<Record<(typeof AUTHORIZE_PARAMS)[number], string | readonly string[] | undefined>>;

export interface AuthorizeRequest {
  clientId: string;
  /** Self-asserted by the client's document: show it beside clientHost, never instead of it. */
  clientName: string;
  /** The client_id URL's host: who is asking, as the allowlist vouches. */
  clientHost: string;
  redirectUri: string;
  /** Show it on the consent page. */
  redirectHost: string;
  /** A loopback redirect: warn that any local process can listen on a port. */
  loopback: boolean;
  codeChallenge: string;
  state: string;
  /** The resource scopes this request may be granted. */
  scopes: string[];
  /** The scope parameter as requested, or null when absent. */
  requestedScope: string | null;
}

/** Show a page; never redirect. */
export type AuthorizePageError = "invalid_client" | "untrusted_client" | "invalid_redirect";

/** Redirected to the verified redirect_uri. */
export type AuthorizeRedirectError = "invalid_request" | "unsupported_response_type" | "invalid_scope" | "invalid_target";

export type AuthorizeCheck =
  | { ok: true; request: AuthorizeRequest }
  | { ok: false; kind: "page"; error: AuthorizePageError }
  | { ok: false; kind: "redirect"; error: AuthorizeRedirectError; redirectUrl: string };

export type ApproveResult =
  | { ok: true; redirectUrl: string }
  | Exclude<AuthorizeCheck, { ok: true }>
  /** No signing key, or the code was not stored: show a "try again" page. */
  | { ok: false; kind: "unavailable" };

export interface ApproveParams {
  /** The same parameters the consent page was shown for, checked again here. */
  params: RawAuthorizeParams | URLSearchParams;
  /** The signed-in person, as the host identifies them. Becomes `sub`. */
  subject: string;
  /** Narrow the grant to these scopes (a subset of the request's). Defaults to all of them. */
  scopes?: readonly string[];
  /** Host data bound to the grant (a tenant id, for example). */
  context?: GrantContext;
}

function single(value: string | readonly string[] | undefined): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

function toRaw(params: RawAuthorizeParams | URLSearchParams): RawAuthorizeParams {
  if (!(params instanceof URLSearchParams)) return params;
  const raw: Record<string, string | string[]> = {};
  for (const name of AUTHORIZE_PARAMS) {
    const values = params.getAll(name);
    if (values.length === 1) raw[name] = values[0]!;
    else if (values.length > 1) raw[name] = values;
  }
  return raw;
}

/**
 * Does a `resource` parameter name this resource? Scheme and host case are
 * forgiven (MCP asks for that), and nothing else: the raw value must be the
 * resource's origin followed by exactly its path. Comparing only the parsed
 * form would let through what the parser drops (userinfo, even an empty `@`,
 * an empty `?` or `#`, backslashes, surrounding space, an explicit default port).
 */
export function sameResource(param: string, resource: string): boolean {
  let url: URL;
  try {
    url = new URL(param);
  } catch {
    return false;
  }
  const head = param.slice(0, url.origin.length);
  const rest = param.slice(url.origin.length);
  const exactPath = rest === url.pathname || (url.pathname === "/" && rest === "");
  return head.toLowerCase() === url.origin && exactPath && canonicalUrl(url) === resource;
}

export function createAuthorize(ctx: Context) {
  const { config } = ctx;

  /** The redirect_uri with `params` and `iss` added; a query it already has is kept. */
  function responseUrl(redirectUri: string, params: Record<string, string>): string {
    const url = new URL(redirectUri);
    for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
    url.searchParams.set("iss", config.issuer);
    return url.toString();
  }

  function errorUrl(redirectUri: string, error: string, state: string | null): string {
    return responseUrl(redirectUri, state === null ? { error } : { error, state });
  }

  async function check(input: RawAuthorizeParams | URLSearchParams): Promise<AuthorizeCheck> {
    const raw = toRaw(input);
    // 1. The client.
    const clientId = single(raw.client_id);
    if (clientId === null) return { ok: false, kind: "page", error: "invalid_client" };
    const clientHost = trustedClientIdHost(clientId, config.clientIdHosts);
    if (clientHost === null) return { ok: false, kind: "page", error: "untrusted_client" };
    const document = await ctx.clientMetadata.fetch(clientId);
    if (!document.ok) return { ok: false, kind: "page", error: "invalid_client" };

    // 2. Where an answer may be sent.
    const redirectUri = single(raw.redirect_uri);
    if (redirectUri === null || !matchesRegisteredRedirect(redirectUri, document.metadata.redirectUris)) {
      return { ok: false, kind: "page", error: "invalid_redirect" };
    }

    // 3. From here on, refusals go back to the client.
    const rawState = single(raw.state);
    const state = rawState !== null && rawState.length <= STATE_MAX_LENGTH ? rawState : null;
    const refuse = (error: AuthorizeRedirectError): AuthorizeCheck => ({
      ok: false,
      kind: "redirect",
      error,
      redirectUrl: errorUrl(redirectUri, error, state),
    });

    if (single(raw.response_type) !== "code") return refuse("unsupported_response_type");
    const codeChallenge = single(raw.code_challenge);
    if (single(raw.code_challenge_method) !== "S256" || codeChallenge === null || !isValidCodeChallenge(codeChallenge)) {
      return refuse("invalid_request");
    }
    if (state === null) return refuse("invalid_request");
    const resource = single(raw.resource);
    if (resource === null) return refuse("invalid_request");
    if (!sameResource(resource, config.resource)) return refuse("invalid_target");

    let requestedScope: string | null = null;
    let asked: string[] = [];
    if (raw.scope !== undefined) {
      requestedScope = single(raw.scope);
      asked = (requestedScope ?? "").split(" ").filter(Boolean);
      if (asked.length === 0 || asked.some((scope) => !config.requestableScopes.includes(scope))) return refuse("invalid_scope");
    }
    // `offline_access` is recognised but never minted; a request naming only it
    // gets the default scopes, and the token response says what was granted.
    const named = config.scopes.filter((scope) => asked.includes(scope));

    return {
      ok: true,
      request: {
        clientId,
        clientName: document.metadata.clientName,
        clientHost,
        redirectUri,
        redirectHost: new URL(redirectUri).host,
        loopback: isLoopbackRedirect(redirectUri),
        codeChallenge,
        state,
        scopes: named.length > 0 ? named : [...config.defaultScopes],
        requestedScope,
      },
    };
  }

  async function approve(input: ApproveParams): Promise<ApproveResult> {
    if (typeof input.subject !== "string" || input.subject === "") throw new TypeError("approve needs a non-empty subject");
    const checked = await check(input.params);
    if (!checked.ok) return checked;
    const request = checked.request;
    const scopes = input.scopes === undefined ? request.scopes : [...input.scopes];
    if (scopes.length === 0 || scopes.some((scope) => !request.scopes.includes(scope))) {
      throw new TypeError("approve scopes must be a non-empty subset of the request's scopes");
    }
    const context = { ...(input.context ?? {}) };
    if (Object.values(context).some((value) => typeof value !== "string")) throw new TypeError("approve context values must be strings");

    // A server that cannot mint access tokens mints no codes.
    try {
      if (!(await ctx.hooks.keys.signingKey())) return { ok: false, kind: "unavailable" };
    } catch (err) {
      ctx.report("keys.signingKey", err);
      return { ok: false, kind: "unavailable" };
    }

    const bare = randomToken(32);
    const approvedAt = config.now();
    let handed: string;
    try {
      handed = ctx.hooks.tokenWrapper ? ctx.hooks.tokenWrapper.wrap("code", bare) : bare;
      await ctx.hooks.codeStore.put(
        sha256Hex(bare),
        {
          subject: input.subject,
          clientId: request.clientId,
          redirectUri: request.redirectUri,
          codeChallenge: request.codeChallenge,
          scopes,
          context,
          authorizedAt: approvedAt,
          expiresAt: approvedAt + config.codeTtlSeconds * 1000,
        },
        config.codeTtlSeconds,
      );
    } catch (err) {
      ctx.report("codeStore.put", err);
      return { ok: false, kind: "unavailable" };
    }
    await ctx.audit({ type: "code.issued", subject: input.subject, clientId: request.clientId, scopes });
    return { ok: true, redirectUrl: responseUrl(request.redirectUri, { code: handed, state: request.state }) };
  }

  /** Where to send the browser when the person says no: `access_denied`, with state and iss. */
  function denialUrl(request: AuthorizeRequest): string {
    return errorUrl(request.redirectUri, "access_denied", request.state);
  }

  return { check, approve, denialUrl };
}

