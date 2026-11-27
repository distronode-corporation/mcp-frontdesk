// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared fixtures. Every URL is an example domain; nothing here touches a network.
 */
import { createFrontdeskWith } from "../src/frontdesk.ts";
import type { AuditEvent, FrontdeskConfig } from "../src/config.ts";
import { generateSigningJwk, keyProviderFromJwk, type KeyProvider } from "../src/keys.ts";
import { MemoryCodeStore, MemoryGrantStore } from "../src/memory-stores.ts";
import type { CodeStore, GrantStore } from "../src/stores.ts";
import { deriveCodeChallenge } from "../src/pkce.ts";
import type { Transport } from "../src/pinned-get.ts";

export const ISSUER = "https://mcp.example.com";
export const RESOURCE = "https://mcp.example.com/mcp";
export const CLIENT_ID = "https://client.example.com/oauth/metadata.json";
export const HOSTED_REDIRECT = "https://client.example.com/callback";
export const LOOPBACK_REDIRECT = "http://127.0.0.1/callback";
export const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const CHALLENGE = deriveCodeChallenge(VERIFIER);
export const T0 = Date.UTC(2030, 0, 1, 12);

export const CLIENT_DOCUMENT = {
  client_id: CLIENT_ID,
  client_name: "Example Client",
  redirect_uris: [HOSTED_REDIRECT, LOOPBACK_REDIRECT],
  token_endpoint_auth_method: "none",
};

/** A clock tests move by hand. */
export function clock(start = T0) {
  let now = start;
  return {
    now: () => now,
    advance(ms: number) {
      now += ms;
    },
  };
}

let sharedKey: Promise<Record<string, unknown>> | undefined;
/** One generated key for the whole run: generation is the slow part. */
export function testJwk(): Promise<Record<string, unknown>> {
  sharedKey ??= generateSigningJwk("test-key") as Promise<Record<string, unknown>>;
  return sharedKey;
}

/** A JSON response. `init.headers` in any form ResponseInit takes; a Content-Type there wins. */
export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { status: 200, ...init, headers });
}

/**
 * What a test drives. `codes`, `grants` and `keys` are the ones `fd` actually
 * uses (an override's, when one was passed), and `clock` is its clock.
 */
export interface Harness {
  fd: ReturnType<typeof createFrontdeskWith>;
  clock: ReturnType<typeof clock>;
  codes: CodeStore;
  grants: GrantStore;
  keys: KeyProvider;
  events: AuditEvent[];
  reports: { where: string; err: unknown }[];
  fetches: string[];
}

/**
 * A Frontdesk over in-memory stores and a hand-moved clock. Override any
 * config field but `now`: pass another harness's `clock` in `options` to
 * share one, so `h.clock` is always the clock `fd` reads.
 */
export async function harness(
  overrides: Partial<Omit<FrontdeskConfig, "now">> = {},
  options: { document?: unknown; transport?: Transport; clock?: ReturnType<typeof clock> } = {},
): Promise<Harness> {
  const time = options.clock ?? clock();
  const keys = await keyProviderFromJwk(await testJwk());
  const events: AuditEvent[] = [];
  const reports: { where: string; err: unknown }[] = [];
  const fetches: string[] = [];
  const document = "document" in options ? options.document : CLIENT_DOCUMENT;
  const config: FrontdeskConfig = {
    issuer: ISSUER,
    resource: RESOURCE,
    scopes: ["notes:read", "notes:write"],
    defaultScopes: ["notes:read"],
    authorizationEndpoint: "/authorize",
    tokenEndpoint: "/token",
    clientIdHosts: ["client.example.com"],
    redirectUris: [HOSTED_REDIRECT],
    allowLoopbackRedirects: true,
    allowedOrigins: ["https://app.example.com"],
    keys,
    codeStore: new MemoryCodeStore({ now: time.now }),
    grantStore: new MemoryGrantStore(),
    reporter: { error: (where, err) => reports.push({ where, err }) },
    audit: { record: (event) => void events.push(event) },
    clientMetadata: {
      unsafeFetchClientMetadata: async (url) => {
        fetches.push(url);
        return jsonResponse(document);
      },
    },
    ...overrides,
    now: time.now,
  };
  const fd = createFrontdeskWith(config, options.transport ? { transport: options.transport } : {});
  return { fd, clock: time, codes: config.codeStore, grants: config.grantStore, keys: config.keys, events, reports, fetches };
}

export function authorizeParams(overrides: Record<string, string | undefined> = {}): Record<string, string> {
  const params: Record<string, string | undefined> = {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: HOSTED_REDIRECT,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    state: "state-123",
    resource: RESOURCE,
    ...overrides,
  };
  return Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined)) as Record<string, string>;
}

/** Approve and return the code from the redirect URL. */
export async function approveCode(h: Harness, extra: Partial<Parameters<Harness["fd"]["approve"]>[0]> = {}, params = authorizeParams()) {
  const result = await h.fd.approve({ params, subject: "user-1", ...extra });
  if (!result.ok) throw new Error(`approve failed: ${JSON.stringify(result)}`);
  return new URL(result.redirectUrl).searchParams.get("code")!;
}

export function tokenRequest(form: Record<string, string>, headers: Record<string, string> = {}, method = "POST"): Request {
  return new Request(`${ISSUER}/token`, {
    method,
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    ...(method === "POST" ? { body: new URLSearchParams(form).toString() } : {}),
  });
}

export function codeForm(code: string, overrides: Record<string, string | undefined> = {}): Record<string, string> {
  const form: Record<string, string | undefined> = {
    grant_type: "authorization_code",
    code,
    code_verifier: VERIFIER,
    redirect_uri: HOSTED_REDIRECT,
    client_id: CLIENT_ID,
    resource: RESOURCE,
    ...overrides,
  };
  return Object.fromEntries(Object.entries(form).filter(([, v]) => v !== undefined)) as Record<string, string>;
}

export function refreshForm(refreshToken: string, overrides: Record<string, string | undefined> = {}): Record<string, string> {
  const form: Record<string, string | undefined> = {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
    ...overrides,
  };
  return Object.fromEntries(Object.entries(form).filter(([, v]) => v !== undefined)) as Record<string, string>;
}

export interface TokenBody {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  error?: string;
}

/** Approve, exchange, and return the token response body. */
export async function connect(h: Harness, extra: Partial<Parameters<Harness["fd"]["approve"]>[0]> = {}): Promise<TokenBody> {
  const code = await approveCode(h, extra);
  const res = await h.fd.handleToken(tokenRequest(codeForm(code)));
  if (res.status !== 200) throw new Error(`exchange failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as TokenBody;
}

export function resourceRequest(token: string | null, path = "/mcp", headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, {
    method: "POST",
    headers: { ...(token === null ? {} : { Authorization: `Bearer ${token}` }), ...headers },
  });
}
