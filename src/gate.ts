// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * The bearer gate for the resource server: who is calling, or the response
 * that tells an MCP client how to find out.
 *
 *   - No Authorization header: 401 with `WWW-Authenticate: Bearer
 *     resource_metadata="..."`, so a client discovers the authorization server.
 *   - A header that is empty or not a well-formed bearer token, or a token that does not
 *     verify, or a request path the token may not be used on: the same 401 with
 *     `error="invalid_token"`, so a client holding one refreshes. Which check
 *     failed is not something the holder of a refused token gets told.
 *   - A valid token without the scopes the caller requires: 403 with
 *     `error="insufficient_scope"` and the scopes needed (MCP step-up).
 *   - A browser `Origin` that is not allowed: 403, before anything else (the
 *     MCP transport's DNS-rebinding rule).
 *   - A rate limiter that says no: 429; one that throws: reported, and 503.
 */
import { verifyAccessToken, type VerifiedAccessToken } from "./access-token.ts";
import type { Context } from "./context.ts";
import { protectedResourceMetadataUrl } from "./discovery.ts";
import { forbiddenOrigin } from "./token-endpoint.ts";

/** The token of a `Bearer <token>` header, or null. One token, no spaces in it. */
export function bearerTokenFrom(header: string | null | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer[ \t]+(\S+)$/i.exec(header.trim());
  return match ? match[1]! : null;
}

export type AuthenticateResult = { ok: true; token: VerifiedAccessToken } | { ok: false; response: Response };

export interface AuthenticateOptions {
  /** Scopes this request needs, all of them. A token missing any gets a 403 step-up challenge. */
  requiredScopes?: readonly string[];
}

export function createGate(ctx: Context) {
  const { config } = ctx;
  const metadataUrl = protectedResourceMetadataUrl(config.resource);

  function challenge(params: Record<string, string>): string {
    const all: Record<string, string> = { resource_metadata: metadataUrl, ...params };
    return `Bearer ${Object.entries(all)
      .map(([name, value]) => `${name}="${value}"`)
      .join(", ")}`;
  }

  /** The 401. `presented` adds `error="invalid_token"`. */
  function unauthorized(presented: boolean): Response {
    return Response.json(presented ? { error: "invalid_token" } : { error: "unauthorized" }, {
      status: 401,
      headers: {
        "WWW-Authenticate": presented ? challenge({ error: "invalid_token" }) : challenge({}),
        "Cache-Control": "no-store",
      },
    });
  }

  /** The 403 step-up challenge naming every scope the request needs. */
  function insufficientScope(scopes: readonly string[]): Response {
    return Response.json(
      { error: "insufficient_scope" },
      {
        status: 403,
        headers: { "WWW-Authenticate": challenge({ error: "insufficient_scope", scope: scopes.join(" ") }), "Cache-Control": "no-store" },
      },
    );
  }

  async function authenticate(request: Request, options: AuthenticateOptions = {}): Promise<AuthenticateResult> {
    const required = options.requiredScopes ?? [];
    if (required.some((scope) => !config.scopes.includes(scope))) {
      throw new TypeError("requiredScopes must be scopes this resource defines");
    }
    if (forbiddenOrigin(ctx, request)) {
      return { ok: false, response: Response.json({ error: "forbidden_origin" }, { status: 403, headers: { "Cache-Control": "no-store" } }) };
    }
    if (ctx.hooks.rateLimiter) {
      let allowed: boolean;
      try {
        allowed = await ctx.hooks.rateLimiter.allow("resource", request);
      } catch (err) {
        // A limiter that cannot answer fails closed, and never throws into the host's handler.
        ctx.report("rateLimiter.resource", err);
        return {
          ok: false,
          response: Response.json({ error: "temporarily_unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } }),
        };
      }
      if (!allowed) {
        return {
          ok: false,
          response: Response.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "60", "Cache-Control": "no-store" } }),
        };
      }
    }
    const header = request.headers.get("authorization");
    // Absent: discovery. Present but empty or malformed: a refused credential.
    if (header === null) return { ok: false, response: unauthorized(false) };
    const token = bearerTokenFrom(header);
    if (!token) return { ok: false, response: unauthorized(true) };
    // The token authenticates on the resource's own paths and nowhere else.
    if (!config.resourcePaths.includes(new URL(request.url).pathname)) return { ok: false, response: unauthorized(true) };
    const verified = await verifyAccessToken(config, ctx.hooks.keys, token);
    if (!verified) return { ok: false, response: unauthorized(true) };
    if (required.some((scope) => !verified.scopes.includes(scope))) return { ok: false, response: insufficientScope(required) };
    return { ok: true, token: verified };
  }

  return { authenticate, unauthorized, insufficientScope };
}
