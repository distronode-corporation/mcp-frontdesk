// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * The example server: plain `node:http`, mcp-frontdesk for OAuth and the bearer
 * gate, and the official MCP TypeScript SDK for the protocol.
 *
 *   /.well-known/...   discovery documents (mcp-frontdesk)
 *   /authorize         the demo sign-in and consent page (this file), which
 *                      calls mcp-frontdesk's checkAuthorizeRequest and approve
 *   /signin            the demo sign-in form's target
 *   /token             the token endpoint (mcp-frontdesk)
 *   /mcp               the MCP endpoint: mcp-frontdesk's gate, then the SDK
 *
 * Loopback http only: it listens on 127.0.0.1 and refuses any other Host
 * header. Everything is in memory and lost on restart.
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createMcpHandler, type AuthInfo } from "@modelcontextprotocol/server";
import {
  bearerTokenFrom,
  claudeClients,
  createFrontdesk,
  generateSigningJwk,
  keyProviderFromJwk,
  MemoryCodeStore,
  MemoryGrantStore,
  type Frontdesk,
  type FrontdeskConfig,
  type RateLimiter,
} from "mcp-frontdesk";

import { readForm, sendWebResponse, toWebRequest } from "./node-http.ts";
import { DEMO_ACCOUNTS, Notebooks, notesServer, SCOPES } from "./notes.ts";
import { consentPage, errorPage, signInPage } from "./pages.ts";

/** The parameters of an authorization request: the only ones carried through the consent form. */
const AUTHORIZE_PARAMS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "code_challenge",
  "code_challenge_method",
  "state",
  "resource",
  "scope",
];

const FORM_MAX_BYTES = 16 * 1024;
const SESSION_COOKIE = "demo_session";

export interface ExampleOptions {
  /** Port on 127.0.0.1. 0 picks a free one. Default 3000. */
  port?: number;
  /** Which clients may connect. Default: the `claudeClients` preset. */
  clients?: Pick<FrontdeskConfig, "clientIdHosts" | "redirectUris" | "allowLoopbackRedirects">;
  /** Passed to mcp-frontdesk as is. Default: the guarded fetch with the system resolver. */
  clientMetadata?: FrontdeskConfig["clientMetadata"];
  refreshTokenReuse?: FrontdeskConfig["refreshTokenReuse"];
  ttl?: FrontdeskConfig["ttl"];
  /** Requests per minute per endpoint, across all callers (a demo-sized limiter). Default 300. */
  rateLimitPerMinute?: number;
  /** Clock in milliseconds, for tests. Default `Date.now`. */
  now?: () => number;
}

export interface ExampleServer {
  /** `http://127.0.0.1:<port>`: the issuer. */
  origin: string;
  /** `<origin>/mcp`: the resource. */
  resource: string;
  frontdesk: Frontdesk;
  notebooks: Notebooks;
  close(): Promise<void>;
}

/**
 * The simplest RateLimiter that does anything: a fixed one-minute window per
 * endpoint. A real server keys it by client address or account, in a store
 * its instances share.
 */
function fixedWindowLimiter(perMinute: number, now: () => number): RateLimiter {
  const windows = new Map<string, { start: number; count: number }>();
  return {
    allow(endpoint) {
      const t = now();
      const window = windows.get(endpoint);
      if (!window || t - window.start >= 60_000) {
        windows.set(endpoint, { start: t, count: 1 });
        return true;
      }
      window.count += 1;
      return window.count <= perMinute;
    },
  };
}

function sameSecret(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function cookie(request: Request, name: string): string | null {
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function redirect(location: string, status = 302, headers: Record<string, string> = {}): Response {
  return new Response(null, { status, headers: { Location: location, "Cache-Control": "no-store", ...headers } });
}

function authorizeParamsOf(source: URLSearchParams): URLSearchParams {
  const params = new URLSearchParams();
  for (const [name, value] of source) if (AUTHORIZE_PARAMS.includes(name)) params.append(name, value);
  return params;
}

export async function startExampleServer(options: ExampleOptions = {}): Promise<ExampleServer> {
  const now = options.now ?? Date.now;
  const server: Server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 3000, "127.0.0.1", () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${port}`;
  const resource = `${origin}/mcp`;
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  // The pages a browser may post the forms from: the same two names the Host check admits.
  const allowedOrigins = new Set([origin, `http://localhost:${port}`]);
  const foreignOrigin = (request: Request) => {
    const requestOrigin = request.headers.get("origin");
    return requestOrigin !== null && !allowedOrigins.has(requestOrigin);
  };

  // A fresh signing key per run. A real server loads one from its secret store.
  const keys = await keyProviderFromJwk(await generateSigningJwk());
  const clients = options.clients ?? claudeClients;

  const frontdesk = createFrontdesk({
    clientIdHosts: clients.clientIdHosts,
    redirectUris: clients.redirectUris,
    ...(clients.allowLoopbackRedirects === undefined ? {} : { allowLoopbackRedirects: clients.allowLoopbackRedirects }),
    issuer: origin,
    resource,
    resourceName: "mcp-frontdesk example notes",
    scopes: [...SCOPES],
    defaultScopes: ["notes:read"],
    authorizationEndpoint: "/authorize",
    tokenEndpoint: "/token",
    allowedOrigins: [],
    keys,
    codeStore: new MemoryCodeStore({ now }),
    grantStore: new MemoryGrantStore(),
    rateLimiter: fixedWindowLimiter(options.rateLimitPerMinute ?? 300, now),
    reporter: { error: (where, err) => console.error(`mcp-frontdesk: ${where}:`, err) },
    ...(options.clientMetadata ? { clientMetadata: options.clientMetadata } : {}),
    ...(options.refreshTokenReuse ? { refreshTokenReuse: options.refreshTokenReuse } : {}),
    ...(options.ttl ? { ttl: options.ttl } : {}),
    now,
  });

  const notebooks = new Notebooks();
  // Both protocol eras: the 2026-07-28 revision, and stateless serving for 2025-era clients.
  const mcp = createMcpHandler(() => notesServer(notebooks));

  /** Demo sessions: a random id in a cookie, the account and a CSRF token in memory. */
  const sessions = new Map<string, { account: string; csrf: string }>();

  async function consent(request: Request): Promise<Response> {
    const isPost = request.method === "POST";
    if (!isPost && request.method !== "GET") return errorPage(405, "Method not allowed.");
    const form = isPost ? await readForm(request, FORM_MAX_BYTES) : null;
    if (isPost && !form) return errorPage(400, "The form could not be read.");
    const params = authorizeParamsOf(form ?? new URL(request.url).searchParams);

    // 1. Is this a request from a client we accept? Before any session is read.
    const check = await frontdesk.checkAuthorizeRequest(params);
    if (!check.ok) {
      // A "page" error never redirects: the client or its redirect_uri is not verified.
      return check.kind === "page" ? errorPage(400, `This connection request was refused (${check.error}).`) : redirect(check.redirectUrl);
    }

    // 2. Who is signed in?
    const sid = cookie(request, SESSION_COOKIE);
    const session = sid ? sessions.get(sid) : undefined;
    if (!session) {
      if (isPost) return errorPage(403, "Your session ended. Start the connection again.");
      return signInPage(`/authorize?${params}`);
    }

    // 3. Ask, or act on the answer.
    if (!isPost) return consentPage(check.request, params, session.csrf, session.account);
    if (foreignOrigin(request) || !sameSecret(form!.get("csrf") ?? "", session.csrf)) {
      return errorPage(403, "This form did not come from this server.");
    }
    if (form!.get("decision") !== "approve") return redirect(frontdesk.denialUrl(check.request));
    const result = await frontdesk.approve({ params, subject: session.account });
    if (!result.ok) {
      return result.kind === "redirect" ? redirect(result.redirectUrl) : errorPage(503, "Something went wrong. Try again.");
    }
    return redirect(result.redirectUrl);
  }

  async function signIn(request: Request): Promise<Response> {
    if (request.method !== "POST") return errorPage(405, "Method not allowed.");
    const form = await readForm(request, FORM_MAX_BYTES);
    const account = DEMO_ACCOUNTS.find((entry) => entry.id === form?.get("account"));
    const next = form?.get("next") ?? "";
    if (!account || !next.startsWith("/authorize?") || foreignOrigin(request)) {
      return errorPage(400, "Sign-in failed.");
    }
    const sid = randomBytes(32).toString("base64url");
    sessions.set(sid, { account: account.id, csrf: randomBytes(32).toString("base64url") });
    // No Secure flag: this demo is http on loopback. A real server uses https and __Host- cookies.
    return redirect(next, 303, { "Set-Cookie": `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax` });
  }

  async function serveMcp(request: Request): Promise<Response> {
    const auth = await frontdesk.authenticate(request);
    if (!auth.ok) return auth.response; // 401 with resource_metadata, 403 or 429
    const authInfo: AuthInfo = {
      token: bearerTokenFrom(request.headers.get("authorization"))!,
      clientId: auth.token.clientId,
      scopes: auth.token.scopes,
      expiresAt: auth.token.expiresAt,
      resource: new URL(resource),
      resourceMetadataUrl: frontdesk.protectedResourceMetadataUrl,
      extra: { subject: auth.token.subject },
    };
    return mcp.fetch(request, { authInfo });
  }

  async function route(request: Request): Promise<Response> {
    const discovery = frontdesk.handleDiscovery(request);
    if (discovery) return discovery;
    switch (new URL(request.url).pathname) {
      case "/token":
        return frontdesk.handleToken(request);
      case "/authorize":
        return consent(request);
      case "/signin":
        return signIn(request);
      case "/mcp":
        return serveMcp(request);
      default:
        return errorPage(404, "Not found.");
    }
  }

  server.on("request", (req, res) => {
    // DNS rebinding: a page on another name that resolves to 127.0.0.1 sends its own Host.
    if (!allowedHosts.has(req.headers.host ?? "")) {
      res.writeHead(421, { "Content-Type": "text/plain" }).end("Misdirected request");
      return;
    }
    const aborted = new AbortController();
    res.on("close", () => aborted.abort());
    const request = toWebRequest(req, origin, aborted.signal);
    if (!request) {
      res.writeHead(400, { "Content-Type": "text/plain" }).end("Bad request");
      return;
    }
    route(request)
      .then((response) => sendWebResponse(res, response))
      .catch((err: unknown) => {
        console.error("example server:", err);
        if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain" });
        res.end();
      });
  });

  return {
    origin,
    resource,
    frontdesk,
    notebooks,
    async close() {
      await mcp.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
