// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * The token endpoint (RFC 6749 section 3.2): `authorization_code` with PKCE
 * S256, and `refresh_token` with rotation. Public clients only (auth method
 * `none`): the code with its verifier, or the refresh token, is the authority.
 *
 *   - The body is form-urlencoded, read through a streaming 8 KB cap, and a
 *     repeated parameter is refused (RFC 6749 section 3.2).
 *   - A client secret or an Authorization header is refused, not ignored.
 *   - Before any code is spent or any token rotated, the signing key must be
 *     there: a burnt code the server could never turn into a token would cost
 *     the person a reconnect for the server's own gap. The key is fetched once
 *     per request and that same key signs the access token.
 *   - Every refusal of a code or a grant is the same `invalid_grant`, so there
 *     is no oracle between "replayed", "wrong verifier", "expired" and "never
 *     existed". The reason goes to the audit sink, never to the client.
 *   - A code store that fails is a refusal, never an issue.
 *   - A spent code presented again revokes the family its first redemption
 *     started (RFC 6749 section 4.1.2), and is answered with the same
 *     `invalid_grant`. The code's tombstone names that family; a replay that
 *     lands while the first redemption is still in flight flags the tombstone,
 *     and the first redemption, seeing the flag after its insert, revokes the
 *     family it just wrote and refuses too.
 *   - A refresh asking for a scope the grant never had is `invalid_scope`, and
 *     is only decided once the token has passed every check, so a dead token
 *     is `invalid_grant` whatever scope it names.
 *   - `Cache-Control: no-store` on every answer.
 */
import { mintAccessToken } from "./access-token.ts";
import { sameResource } from "./authorize.ts";
import { OFFLINE_ACCESS, type GrantInfo } from "./config.ts";
import type { Context } from "./context.ts";
import { sha256Hex } from "./encoding.ts";
import { createGrant, grantIsActive, liveScopes, rotateGrant } from "./grants.ts";
import { deriveCodeChallenge, isValidCodeVerifier } from "./pkce.ts";
import type { SigningKey } from "./keys.ts";
import { readCapped } from "./read-capped.ts";
import type { CodeRecord } from "./stores.ts";

/** A real token request is a few hundred bytes. */
export const TOKEN_REQUEST_MAX_BYTES = 8 * 1024;

/**
 * How much longer than the code's own lifetime a spent code's tombstone is
 * kept: 10 minutes. The first redemption and any replay both happen while the
 * code is valid, so this only has to cover clock skew between instances and a
 * slow retry; it keeps the store at one small entry per sign-in, for minutes.
 */
export const SPENT_CODE_GRACE_SECONDS = 10 * 60;

const NO_STORE = { "Cache-Control": "no-store", Pragma: "no-cache" } as const;

export type TokenError =
  | "invalid_request"
  | "invalid_grant"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "invalid_target"
  | "temporarily_unavailable"
  | "server_error";

/** CORS headers for an allowed browser origin; none for a request with no Origin. */
export function corsHeaders(ctx: Context, request: Request): Record<string, string> {
  const origin = request.headers.get("origin");
  return origin !== null && ctx.config.allowedOrigins.includes(origin)
    ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" }
    : {};
}

/** An Origin header that is present and not allowed. */
export function forbiddenOrigin(ctx: Context, request: Request): boolean {
  const origin = request.headers.get("origin");
  return origin !== null && !ctx.config.allowedOrigins.includes(origin);
}

export function createTokenEndpoint(ctx: Context) {
  const { config, hooks } = ctx;

  function json(request: Request, body: Record<string, unknown>, status = 200, extra: Record<string, string> = {}): Response {
    return Response.json(body, { status, headers: { ...NO_STORE, ...corsHeaders(ctx, request), ...extra } });
  }
  const error = (request: Request, code: TokenError, status = 400) => json(request, { error: code }, status);

  async function readForm(request: Request): Promise<Map<string, string> | null> {
    const media = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (media !== "application/x-www-form-urlencoded") return null;
    const read = await readCapped(request.body, TOKEN_REQUEST_MAX_BYTES, request.headers.get("content-length"));
    if (!read.ok) return null;
    const form = new Map<string, string>();
    for (const [name, value] of new URLSearchParams(Buffer.from(read.bytes).toString("utf8"))) {
      if (form.has(name)) return null;
      form.set(name, value);
    }
    return form;
  }

  const resourceOk = (form: Map<string, string>) => !form.has("resource") || sameResource(form.get("resource")!, config.resource);

  /**
   * The access token for `info`, signed with the key this request already
   * holds. Called by createGrant and rotateGrant before they write to the
   * store, so a throw here (a claims hook) spends nothing.
   */
  const minter = (key: SigningKey) => async (info: GrantInfo): Promise<string> => {
    const extra = hooks.accessTokenClaims ? await hooks.accessTokenClaims(info) : {};
    return mintAccessToken(config, key, info, extra);
  };

  function tokenResponse(request: Request, info: GrantInfo, accessToken: string, refreshToken: string): Response {
    return json(request, {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.accessTtlSeconds,
      refresh_token: refreshToken,
      scope: info.scopes.join(" "),
    });
  }

  async function refused(request: Request, grantType: "authorization_code" | "refresh_token", reason: string, code: TokenError = "invalid_grant") {
    await ctx.audit({ type: "token.refused", grantType, reason });
    return error(request, code);
  }

  /** A take found no record: if the code was spent, revoke what its first redemption started. */
  async function spentCode(request: Request, codeHash: string): Promise<Response> {
    let familyId: string | null;
    try {
      familyId = await hooks.codeStore.markReplayed(codeHash);
    } catch (err) {
      ctx.report("codeStore.markReplayed", err);
      return refused(request, "authorization_code", "store_failed");
    }
    if (familyId === null) return refused(request, "authorization_code", "unknown");
    // A grant store failure here propagates (500), as everywhere else: a retry revokes again.
    const revoked = await hooks.grantStore.revokeFamily(familyId, new Date(config.now()));
    await ctx.audit({ type: "code.replayed", familyId, revoked });
    return refused(request, "authorization_code", "replayed");
  }

  /** After the insert: did a replay land while this redemption was in flight? A store that cannot say counts as yes. */
  async function replayedInFlight(codeHash: string): Promise<boolean> {
    try {
      return await hooks.codeStore.wasReplayed(codeHash);
    } catch (err) {
      ctx.report("codeStore.wasReplayed", err);
      return true;
    }
  }

  async function authorizationCode(request: Request, form: Map<string, string>, clientId: string, key: SigningKey): Promise<Response> {
    const code = form.get("code");
    const verifier = form.get("code_verifier");
    const redirectUri = form.get("redirect_uri");
    if (!code || !verifier || !redirectUri) return error(request, "invalid_request");
    if (!resourceOk(form)) return error(request, "invalid_target");
    // Before the code is spent: a verifier that cannot satisfy PKCE should not burn a good code.
    if (!isValidCodeVerifier(verifier)) return refused(request, "authorization_code", "malformed_verifier");
    const bare = hooks.tokenWrapper ? hooks.tokenWrapper.unwrap("code", code) : code;
    if (bare === null) return refused(request, "authorization_code", "unknown");

    const codeHash = sha256Hex(bare);
    // Chosen before the take, so the tombstone the take leaves can name it.
    const familyId = crypto.randomUUID();
    let record: CodeRecord | null;
    try {
      record = await hooks.codeStore.take(codeHash, { familyId, ttlSeconds: config.codeTtlSeconds + SPENT_CODE_GRACE_SECONDS });
    } catch (err) {
      ctx.report("codeStore.take", err);
      return refused(request, "authorization_code", "store_failed");
    }
    // The code is gone now, whatever the checks below say.
    if (record === null) return spentCode(request, codeHash);
    if (record.expiresAt <= config.now()) return refused(request, "authorization_code", "expired");
    if (record.clientId !== clientId) return refused(request, "authorization_code", "client_mismatch");
    // Exact, port included: the token request names the very URI the code was sent to (RFC 6749 section 4.1.3).
    if (record.redirectUri !== redirectUri) return refused(request, "authorization_code", "redirect_mismatch");
    if (deriveCodeChallenge(verifier) !== record.codeChallenge) return refused(request, "authorization_code", "pkce_mismatch");

    // A scope removed from the config since the approval is dropped (the response's `scope` says so).
    const scopes = liveScopes(ctx, record.scopes);
    if (scopes.length === 0) return refused(request, "authorization_code", "no_scope");
    // When the person said yes, not when the client redeemed the code: a cutoff
    // (a password reset, say) between the two must still end the grant.
    const authorizedAt = new Date(record.authorizedAt);
    const pending: GrantInfo = {
      subject: record.subject,
      clientId,
      scopes,
      context: { ...record.context },
      familyId: null,
      authorizedAt,
    };
    if (!(await grantIsActive(ctx, pending))) return refused(request, "authorization_code", "inactive");

    const grant = await createGrant(
      ctx,
      { familyId, subject: record.subject, clientId, scopes, context: record.context, authorizedAt },
      minter(key),
    );
    if (await replayedInFlight(codeHash)) {
      // The replay found no family to revoke yet: end it here, before any token leaves.
      await hooks.grantStore.revokeFamily(familyId, new Date(config.now()));
      await ctx.audit({ type: "grant.revoked", subject: record.subject, clientId, familyId, reason: "code_reuse" });
      return refused(request, "authorization_code", "replayed");
    }
    return tokenResponse(request, grant.info, grant.issued, grant.refreshToken);
  }

  async function refreshToken(request: Request, form: Map<string, string>, clientId: string, key: SigningKey): Promise<Response> {
    const presented = form.get("refresh_token");
    if (!presented) return error(request, "invalid_request");
    if (!resourceOk(form)) return error(request, "invalid_target");
    // RFC 6749 section 6, in two steps, both before the rotation so a refused
    // scope never costs the client its refresh token. Here, independent of the
    // token: a scope this server does not recognise. In rotateGrant, after every
    // check of the token: a scope the grant does not hold. `offline_access` is
    // what a refresh token is, so it is never "more" than the grant.
    const asked = form.get("scope");
    let requested: string[] | null = null;
    if (asked !== undefined) {
      const scopes = asked.split(" ").filter(Boolean);
      if (scopes.length === 0 || scopes.some((scope) => !config.requestableScopes.includes(scope))) {
        return error(request, "invalid_scope");
      }
      requested = scopes.filter((scope) => scope !== OFFLINE_ACCESS);
    }
    const rotated = await rotateGrant(ctx, presented, clientId, requested, minter(key));
    if (!rotated.ok) {
      return refused(request, "refresh_token", rotated.reason, rotated.reason === "scope_not_granted" ? "invalid_scope" : "invalid_grant");
    }
    return tokenResponse(request, rotated.grant.info, rotated.grant.issued, rotated.grant.refreshToken);
  }

  return async function handleToken(request: Request): Promise<Response> {
    try {
      if (forbiddenOrigin(ctx, request)) return json(request, { error: "invalid_request" }, 403);
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            ...NO_STORE,
            ...corsHeaders(ctx, request),
            "Access-Control-Allow-Methods": "POST",
            "Access-Control-Allow-Headers": "Content-Type",
          },
        });
      }
      if (request.method !== "POST") return json(request, { error: "invalid_request" }, 405, { Allow: "POST, OPTIONS" });
      if (hooks.rateLimiter && !(await hooks.rateLimiter.allow("token", request))) {
        return json(request, { error: "slow_down" }, 429, { "Retry-After": "60" });
      }
      const form = await readForm(request);
      if (!form) return error(request, "invalid_request");
      const clientId = form.get("client_id");
      if (!clientId) return error(request, "invalid_request");
      if (form.has("client_secret") || request.headers.has("authorization")) return error(request, "invalid_request");
      const grantType = form.get("grant_type");
      if (grantType !== "authorization_code" && grantType !== "refresh_token") {
        return error(request, grantType ? "unsupported_grant_type" : "invalid_request");
      }
      let key: SigningKey | null;
      try {
        key = await hooks.keys.signingKey();
      } catch (err) {
        ctx.report("keys.signingKey", err);
        key = null;
      }
      if (!key) return error(request, "temporarily_unavailable", 503);
      return grantType === "authorization_code"
        ? await authorizationCode(request, form, clientId, key)
        : await refreshToken(request, form, clientId, key);
    } catch (err) {
      ctx.report("tokenEndpoint", err);
      return error(request, "server_error", 500);
    }
  };
}
