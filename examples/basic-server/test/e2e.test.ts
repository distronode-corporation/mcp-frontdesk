// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * End to end, over real sockets on 127.0.0.1: the example server, a client's
 * metadata document served by this test, and the official MCP SDK client.
 *
 * About the client's metadata document. A client_id is an https URL on the
 * default port, and mcp-frontdesk's SSRF guard refuses any host that resolves
 * to a loopback or private address, an injected resolver included. That is the
 * point of the guard, and the last test below shows it holding. So a document
 * served on loopback can only be reached through the option whose name says it
 * skips the guard, `unsafeFetchClientMetadata`. The test passes one that
 * answers for the one client host it serves and refuses everything else; the
 * deadline, the 5 KB cap and every document check still run on what it returns.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  Client,
  InsufficientScopeError,
  StreamableHTTPClientTransport,
  UnauthorizedError,
  type OAuthClientProvider,
} from "@modelcontextprotocol/client";
import type { FrontdeskConfig } from "mcp-frontdesk";

import { startExampleServer, type ExampleOptions, type ExampleServer } from "../src/server.ts";

const CLIENT_HOST = "client.example.com";
const CLIENT_ID = `https://${CLIENT_HOST}/oauth/client-metadata.json`;
const REDIRECT_URI = "http://127.0.0.1:53682/callback";
const CLIENTS = { clientIdHosts: [CLIENT_HOST], redirectUris: [], allowLoopbackRedirects: true };

// ---------------------------------------------------------------------------
// The client's metadata document, served by this test on loopback.

let documentServer: Server;
let documentOrigin: string;
const documentHits: string[] = [];

before(async () => {
  documentServer = createServer((req, res) => {
    documentHits.push(req.url ?? "");
    if (req.url !== "/oauth/client-metadata.json") return void res.writeHead(404).end();
    res.writeHead(200, { "Content-Type": "application/json" }).end(
      JSON.stringify({
        client_id: CLIENT_ID,
        client_name: "Example Notes Client",
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: "none",
      }),
    );
  });
  await new Promise<void>((resolve) => documentServer.listen(0, "127.0.0.1", resolve));
  documentOrigin = `http://127.0.0.1:${(documentServer.address() as AddressInfo).port}`;
});

after(async () => {
  documentServer.closeAllConnections();
  await new Promise<void>((resolve) => documentServer.close(() => resolve()));
});

/** Fetches documents for CLIENT_HOST from this test's server, and nothing else. */
function documentFromLoopback(): FrontdeskConfig["clientMetadata"] {
  return {
    unsafeFetchClientMetadata: async (url, init) => {
      const target = new URL(url);
      if (target.host !== CLIENT_HOST) throw new Error(`unexpected client_id host ${target.host}`);
      return fetch(`${documentOrigin}${target.pathname}`, { signal: init.signal, redirect: "manual" });
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers.

/** A clock the tests move by hand. */
function clock() {
  let t = Date.now();
  return { now: () => t, advance: (seconds: number) => void (t += seconds * 1000) };
}

async function start(options: ExampleOptions = {}): Promise<ExampleServer> {
  return startExampleServer({ port: 0, clients: CLIENTS, clientMetadata: documentFromLoopback(), ...options });
}

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

function form(fields: Record<string, string>): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  };
}

function hiddenFields(html: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const match of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    fields[match[1]!] = match[2]!.replace(/&#(\d+);/g, (_, code: string) => String.fromCharCode(Number(code)));
  }
  return fields;
}

interface Discovered {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  resource: string;
}

/** Step 1: from an unauthenticated MCP request to the authorization server's endpoints. */
async function discover(resource: string): Promise<Discovered> {
  const unauthenticated = await fetch(resource, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  assert.equal(unauthenticated.status, 401);
  const challenge = unauthenticated.headers.get("www-authenticate") ?? "";
  const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge)?.[1];
  assert.ok(metadataUrl, `no resource_metadata in ${challenge}`);

  const prm = (await (await fetch(metadataUrl)).json()) as { resource: string; authorization_servers: string[]; scopes_supported: string[] };
  assert.equal(prm.resource, resource);
  assert.deepEqual(prm.scopes_supported, ["notes:read", "notes:write"]);
  const issuer = prm.authorization_servers[0]!;

  const asm = (await (await fetch(`${issuer}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
  assert.equal(asm.issuer, issuer);
  assert.equal(asm.client_id_metadata_document_supported, true);
  assert.deepEqual(asm.code_challenge_methods_supported, ["S256"]);
  assert.equal(asm.registration_endpoint, undefined);
  return { authorizationEndpoint: asm.authorization_endpoint as string, tokenEndpoint: asm.token_endpoint as string, resource: prm.resource };
}

interface Consent {
  /** The consent form's fields, CSRF token included. */
  fields: Record<string, string>;
  html: string;
  cookie: string;
  verifier: string;
  state: string;
}

/** Steps 2 and 3: the authorization request, the demo sign-in, and the consent page. */
async function openConsent(d: Discovered, account: string, scope?: string): Promise<Consent> {
  const { verifier, challenge } = pkce();
  const state = randomBytes(16).toString("base64url");
  const url = new URL(d.authorizationEndpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    resource: d.resource,
    ...(scope ? { scope } : {}),
  }).toString();

  // Not signed in: the demo sign-in page.
  const signInPage = await fetch(url, { redirect: "manual" });
  assert.equal(signInPage.status, 200);
  const signIn = hiddenFields(await signInPage.text());
  assert.equal(signIn.next, `${url.pathname}${url.search}`);

  const signedIn = await fetch(new URL("/signin", url), form({ account, next: signIn.next! }));
  assert.equal(signedIn.status, 303);
  const cookie = (signedIn.headers.get("set-cookie") ?? "").split(";")[0]!;
  assert.match(cookie, /^demo_session=/);
  assert.equal(new URL(signedIn.headers.get("location")!, url).href, url.href);

  // Signed in: the consent page, naming the client and the host that vouches for it.
  const consentPage = await fetch(url, { headers: { Cookie: cookie }, redirect: "manual" });
  assert.equal(consentPage.status, 200);
  assert.equal(consentPage.headers.get("x-frame-options"), "DENY");
  const html = await consentPage.text();
  assert.match(html, /Example Notes Client<\/strong> \(from <code>client\.example\.com<\/code>\)/);
  return { fields: hiddenFields(html), html, cookie, verifier, state };
}

/** Step 3, the answer: approve, and the code in the redirect. */
async function approve(d: Discovered, consent: Consent): Promise<string> {
  const answer = await fetch(d.authorizationEndpoint, {
    ...form({ ...consent.fields, decision: "approve" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: consent.cookie },
  });
  assert.equal(answer.status, 302);
  const back = new URL(answer.headers.get("location")!);
  assert.equal(`${back.origin}${back.pathname}`, REDIRECT_URI);
  assert.equal(back.searchParams.get("state"), consent.state);
  assert.equal(back.searchParams.get("iss"), new URL(d.authorizationEndpoint).origin);
  return back.searchParams.get("code")!;
}

interface Tokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

async function tokenRequest(d: Discovered, fields: Record<string, string>): Promise<Response> {
  return fetch(d.tokenEndpoint, form(fields));
}

/** Step 4: the code, with its PKCE verifier, for tokens. */
async function exchange(d: Discovered, code: string, verifier: string): Promise<Tokens> {
  const res = await tokenRequest(d, {
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    resource: d.resource,
  });
  assert.equal(res.status, 200, await res.clone().text());
  return (await res.json()) as Tokens;
}

async function refresh(d: Discovered, refreshToken: string): Promise<Response> {
  return tokenRequest(d, { grant_type: "refresh_token", refresh_token: refreshToken, client_id: CLIENT_ID });
}

async function connect(d: Discovered, account = "user-1", scope?: string): Promise<Tokens> {
  const consent = await openConsent(d, account, scope);
  return exchange(d, await approve(d, consent), consent.verifier);
}

/**
 * The protocol eras the SDK serves: the 2026-07-28 revision, and a 2025-era
 * client (the SDK client's default handshake), which the server answers statelessly.
 */
const ERAS = ["2026-07-28", "2025"] as const;
type Era = (typeof ERAS)[number];

/** Every HTTP answer the SDK client received: status and WWW-Authenticate. */
const answers: { status: number; challenge: string | null }[] = [];

/** The official MCP SDK client, presenting `accessToken`. */
async function mcpClient(resource: string, accessToken: string, era: Era): Promise<Client> {
  const client = new Client(
    { name: "e2e-test", version: "0.0.0" },
    era === "2026-07-28" ? { versionNegotiation: { mode: { pin: "2026-07-28" } } } : {},
  );
  const transport = new StreamableHTTPClientTransport(new URL(resource), {
    authProvider: { token: async () => accessToken },
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      answers.push({ status: res.status, challenge: res.headers.get("www-authenticate") });
      return res;
    },
  });
  await client.connect(transport);
  return client;
}

async function callTool(resource: string, accessToken: string, name: string, args: Record<string, unknown>, era: Era) {
  const client = await mcpClient(resource, accessToken, era);
  try {
    return await client.callTool({ name, arguments: args });
  } finally {
    await client.close();
  }
}

function textOf(result: Awaited<ReturnType<typeof callTool>>): unknown {
  const first = (result.content as { type: string; text: string }[])[0]!;
  assert.equal(first.type, "text");
  return JSON.parse(first.text);
}

async function invalidGrant(res: Response): Promise<void> {
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "invalid_grant" });
}

// ---------------------------------------------------------------------------

describe("the example server, end to end", () => {
  it("discovery, authorize with PKCE, approve, token, a tool call, refresh, replay, and the family revoked", async () => {
    const time = clock();
    const example = await start({ now: time.now });
    try {
      // 1. Discovery.
      const d = await discover(example.resource);
      assert.equal(d.authorizationEndpoint, `${example.origin}/authorize`);
      assert.equal(d.tokenEndpoint, `${example.origin}/token`);

      // 2 to 4. Authorize, sign in, approve, exchange the code.
      const hitsBefore = documentHits.length;
      const first = await connect(d);
      assert.ok(documentHits.length > hitsBefore, "the client's metadata document was fetched");
      assert.equal(first.token_type, "Bearer");
      assert.equal(first.scope, "notes:read");
      assert.equal(first.expires_in, 600);

      // 5. Tool calls through the official MCP SDK client, in both protocol eras.
      for (const era of ERAS) {
        const client = await mcpClient(example.resource, first.access_token, era);
        const tools = (await client.listTools()).tools.map((tool) => tool.name).sort();
        assert.deepEqual(tools, ["add_note", "list_notes", "read_note"], era);
        const notes = textOf(await client.callTool({ name: "list_notes", arguments: {} })) as { id: string; title: string }[];
        assert.deepEqual(
          notes.map((note) => note.title),
          ["Garden plan", "Book list"],
          era,
        );
        const note = textOf(await client.callTool({ name: "read_note", arguments: { id: notes[0]!.id } })) as { body: string };
        assert.match(note.body, /Tomatoes/, era);
        await client.close();
      }

      // 6. Refresh: a new pair, and the new access token works.
      const refreshed = await refresh(d, first.refresh_token);
      assert.equal(refreshed.status, 200);
      const second = (await refreshed.json()) as Tokens;
      assert.notEqual(second.refresh_token, first.refresh_token);
      assert.notEqual(second.access_token, first.access_token);
      assert.equal((textOf(await callTool(example.resource, second.access_token, "list_notes", {}, "2026-07-28")) as unknown[]).length, 2);
      assert.equal((await example.frontdesk.listGrants("user-1")).length, 1);

      // 7. Replay the rotated refresh token: refused...
      await invalidGrant(await refresh(d, first.refresh_token));

      // 8. ...and the whole family is revoked (the default policy): the successor is refused too.
      await invalidGrant(await refresh(d, second.refresh_token));
      assert.deepEqual(await example.frontdesk.listGrants("user-1"), []);

      // An access token is not looked up: one already minted works until it expires (ttl.accessToken)...
      assert.equal((textOf(await callTool(example.resource, second.access_token, "list_notes", {}, "2026-07-28")) as unknown[]).length, 2);
      // ...and not after.
      time.advance(600 + 6);
      const expired = await fetch(example.resource, {
        method: "POST",
        headers: { Authorization: `Bearer ${second.access_token}`, "Content-Type": "application/json" },
        body: "{}",
      });
      assert.equal(expired.status, 401);
      assert.match(expired.headers.get("www-authenticate") ?? "", /error="invalid_token"/);
      for (const era of ERAS) {
        await assert.rejects(callTool(example.resource, second.access_token, "list_notes", {}, era), UnauthorizedError, era);
      }
    } finally {
      await example.close();
    }
  });

  it('with refreshTokenReuse "refuse", a replay is refused and the successor keeps working', async () => {
    const example = await start({ refreshTokenReuse: "refuse" });
    try {
      const d = await discover(example.resource);
      const first = await connect(d);
      const second = (await (await refresh(d, first.refresh_token)).json()) as Tokens;

      await invalidGrant(await refresh(d, first.refresh_token));

      const third = await refresh(d, second.refresh_token);
      assert.equal(third.status, 200);
      const tokens = (await third.json()) as Tokens;
      assert.equal((textOf(await callTool(example.resource, tokens.access_token, "list_notes", {}, "2026-07-28")) as unknown[]).length, 2);
      assert.equal((await example.frontdesk.listGrants("user-1")).length, 1);
    } finally {
      await example.close();
    }
  });

  it("keeps each account's notes apart, and asks a read-only token to step up for add_note", async () => {
    const example = await start();
    try {
      const d = await discover(example.resource);
      const writer = await connect(d, "user-2", "notes:read notes:write");
      assert.equal(writer.scope, "notes:read notes:write");
      const added = textOf(
        await callTool(example.resource, writer.access_token, "add_note", { title: "Ideas", body: "A kite." }, "2026-07-28"),
      ) as { id: string };
      const mine = textOf(await callTool(example.resource, writer.access_token, "list_notes", {}, "2025")) as { title: string }[];
      assert.deepEqual(
        mine.map((note) => note.title),
        ["Trip checklist", "Ideas"],
      );

      const reader = await connect(d, "user-1");
      assert.equal(reader.scope, "notes:read");
      const theirs = await callTool(example.resource, reader.access_token, "read_note", { id: added.id }, "2026-07-28");
      assert.equal(theirs.isError, true);

      // A tool call that needs more scope gets the 403 step-up challenge, naming the same metadata document.
      for (const era of ERAS) {
        answers.length = 0;
        const refused = callTool(example.resource, reader.access_token, "add_note", { title: "No", body: "" }, era);
        await assert.rejects(refused, (err: unknown) => err instanceof InsufficientScopeError && err.requiredScope === "notes:write", era);
        const last = answers.at(-1)!;
        assert.equal(last.status, 403, era);
        assert.match(last.challenge ?? "", /error="insufficient_scope"/, era);
        assert.match(last.challenge ?? "", /scope="notes:write"/, era);
        assert.ok(last.challenge?.includes(`resource_metadata="${example.frontdesk.protectedResourceMetadataUrl}"`), era);
      }
      assert.equal(example.notebooks.list("user-1").length, 2);
    } finally {
      await example.close();
    }
  });

  it("asks a write-only token to step up for the read tools", async () => {
    const example = await start();
    try {
      const d = await discover(example.resource);
      const writer = await connect(d, "user-1", "notes:write");
      assert.equal(writer.scope, "notes:write");
      for (const [tool, args] of [
        ["list_notes", {}],
        ["read_note", { id: "note-1" }],
      ] as const) {
        answers.length = 0;
        const refused = callTool(example.resource, writer.access_token, tool, args, "2026-07-28");
        await assert.rejects(refused, (err: unknown) => err instanceof InsufficientScopeError && err.requiredScope === "notes:read", tool);
        assert.equal(answers.at(-1)?.status, 403, tool);
        assert.match(answers.at(-1)?.challenge ?? "", /scope="notes:read"/, tool);
      }
      // The write tool still works with the scope it needs.
      const added = textOf(await callTool(example.resource, writer.access_token, "add_note", { title: "Only", body: "Write." }, "2026-07-28"));
      assert.equal((added as { title: string }).title, "Only");
    } finally {
      await example.close();
    }
  });

  it("the sign-in and consent forms accept a page opened at localhost as well as 127.0.0.1, and nothing else", async () => {
    const example = await start();
    try {
      const d = await discover(example.resource);
      const { port } = new URL(example.origin);
      const localhost = `http://localhost:${port}`;
      // fetch cannot set Host, and "localhost" may resolve to ::1, where nothing listens. So each
      // request below goes to 127.0.0.1 carrying exactly what a browser on http://localhost sends:
      // `Host: localhost:<port>`, and that page's Origin on the form posts.
      const atLocalhost = (path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) =>
        new Promise<{ status: number; location: string | null; cookie: string | null; text: string }>((resolve, reject) => {
          const req = httpRequest(
            {
              host: "127.0.0.1",
              port,
              path,
              method: init.method ?? "GET",
              headers: { Host: `localhost:${port}`, ...(init.body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}), ...init.headers },
            },
            (res) => {
              let text = "";
              res.setEncoding("utf8");
              res.on("data", (chunk: string) => (text += chunk));
              res.on("end", () => {
                const setCookie = res.headers["set-cookie"]?.[0];
                resolve({ status: res.statusCode ?? 0, location: res.headers.location ?? null, cookie: setCookie ? setCookie.split(";")[0]! : null, text });
              });
            },
          );
          req.on("error", reject);
          req.end(init.body);
        });
      const post = (path: string, fields: Record<string, string>, headers: Record<string, string>) =>
        atLocalhost(path, { method: "POST", headers, body: new URLSearchParams(fields).toString() });

      const { challenge } = pkce();
      const authorize = new URL(d.authorizationEndpoint);
      authorize.search = new URLSearchParams({
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "localhost-state",
        resource: d.resource,
      }).toString();
      const path = `${authorize.pathname}${authorize.search}`;

      // The authorization page, opened at localhost: the demo sign-in.
      const signInPage = await atLocalhost(path);
      assert.equal(signInPage.status, 200);
      const next = hiddenFields(signInPage.text).next!;
      assert.equal(next, path);

      // Signing in from that page works; from a foreign page it does not.
      assert.equal((await post("/signin", { account: "user-1", next }, { Origin: "http://attacker.example.com" })).status, 400);
      const signedIn = await post("/signin", { account: "user-1", next }, { Origin: localhost });
      assert.equal(signedIn.status, 303);
      assert.match(signedIn.cookie ?? "", /^demo_session=/);

      // The localhost session sees the consent page.
      const consentPage = await atLocalhost(path, { headers: { Cookie: signedIn.cookie! } });
      assert.equal(consentPage.status, 200);
      const fields = hiddenFields(consentPage.text);

      // Approving from a foreign page is refused; from the localhost page it mints a code.
      const answer = (origin: string) => post(authorize.pathname, { ...fields, decision: "approve" }, { Cookie: signedIn.cookie!, Origin: origin });
      assert.equal((await answer("http://attacker.example.com")).status, 403);
      const approved = await answer(localhost);
      assert.equal(approved.status, 302);
      const back = new URL(approved.location!);
      assert.equal(back.searchParams.get("state"), "localhost-state");
      assert.ok(back.searchParams.get("code"));

      // And the same forms still accept the 127.0.0.1 page.
      const local = await fetch(new URL("/signin", example.origin), {
        ...form({ account: "user-1", next }),
        headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: example.origin },
      });
      assert.equal(local.status, 303);
    } finally {
      await example.close();
    }
  });

  it("the official SDK client's own OAuth flow: discovery, the metadata document, PKCE, state, iss, and a refresh on expiry", async () => {
    const time = clock();
    const example = await start({ now: time.now });
    try {
      const saved: {
        tokens?: Awaited<ReturnType<OAuthClientProvider["tokens"]>>;
        verifier?: string;
        discovery?: Parameters<NonNullable<OAuthClientProvider["saveDiscoveryState"]>>[0];
        authorizationUrl?: URL;
      } = {};
      let state = "";
      let refreshes = 0;
      const provider: OAuthClientProvider = {
        redirectUrl: REDIRECT_URI,
        clientMetadataUrl: CLIENT_ID,
        clientMetadata: { client_name: "Example Notes Client", redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: "none" },
        state: () => (state = randomBytes(16).toString("base64url")),
        clientInformation: () => ({ client_id: CLIENT_ID }),
        tokens: () => saved.tokens,
        saveTokens: (tokens) => {
          if (saved.tokens) refreshes += 1;
          saved.tokens = tokens;
        },
        redirectToAuthorization: (url) => void (saved.authorizationUrl = url),
        saveCodeVerifier: (verifier) => void (saved.verifier = verifier),
        codeVerifier: () => saved.verifier!,
        saveDiscoveryState: (discovery) => void (saved.discovery = discovery),
        discoveryState: () => saved.discovery,
      };
      const transport = () => new StreamableHTTPClientTransport(new URL(example.resource), { authProvider: provider });

      // The SDK discovers the authorization server and sends the person to it.
      const first = transport();
      await assert.rejects(new Client({ name: "e2e-test", version: "0.0.0" }).connect(first), UnauthorizedError);
      const authorizationUrl = saved.authorizationUrl!;
      assert.equal(`${authorizationUrl.origin}${authorizationUrl.pathname}`, `${example.origin}/authorize`);
      assert.equal(authorizationUrl.searchParams.get("client_id"), CLIENT_ID);
      assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
      assert.equal(authorizationUrl.searchParams.get("resource"), example.resource);

      // The person signs in and approves (what a browser would do).
      const signIn = await fetch(new URL("/signin", example.origin), form({ account: "user-1", next: `${authorizationUrl.pathname}${authorizationUrl.search}` }));
      const cookie = (signIn.headers.get("set-cookie") ?? "").split(";")[0]!;
      const fields = hiddenFields(await (await fetch(authorizationUrl, { headers: { Cookie: cookie } })).text());
      const answer = await fetch(new URL("/authorize", example.origin), {
        ...form({ ...fields, decision: "approve" }),
        headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie },
      });
      const callback = new URL(answer.headers.get("location")!);
      assert.equal(callback.searchParams.get("state"), state);

      // The SDK redeems the code (checking iss) and connects.
      await first.finishAuth(callback.searchParams);
      const client = new Client({ name: "e2e-test", version: "0.0.0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
      await client.connect(transport());
      assert.equal((textOf(await client.callTool({ name: "list_notes", arguments: {} })) as unknown[]).length, 2);

      // Past the access token's lifetime, the SDK refreshes on the 401 and carries on.
      time.advance(600 + 6);
      assert.equal((textOf(await client.callTool({ name: "list_notes", arguments: {} })) as unknown[]).length, 2);
      assert.equal(refreshes, 1);
      await client.close();
    } finally {
      await example.close();
    }
  });

  it("the consent page: deny, a missing CSRF token, a foreign Host header", async () => {
    const example = await start();
    try {
      const d = await discover(example.resource);
      const consent = await openConsent(d, "user-1");
      const post = (fields: Record<string, string>) =>
        fetch(d.authorizationEndpoint, {
          ...form(fields),
          headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: consent.cookie },
        });

      const forged = await post({ ...consent.fields, csrf: "forged", decision: "approve" });
      assert.equal(forged.status, 403);
      const noSession = await fetch(d.authorizationEndpoint, form({ ...consent.fields, decision: "approve" }));
      assert.equal(noSession.status, 403);

      const denied = await post({ ...consent.fields, decision: "deny" });
      assert.equal(denied.status, 302);
      const back = new URL(denied.headers.get("location")!);
      assert.equal(back.searchParams.get("error"), "access_denied");
      assert.equal(back.searchParams.get("state"), consent.state);

      // Nothing was minted for any of them.
      assert.deepEqual(await example.frontdesk.listGrants("user-1"), []);

      // fetch cannot set Host, so a raw request plays the page on another name (DNS rebinding).
      const rebound = await new Promise<number>((resolve, reject) => {
        const url = new URL(example.resource);
        httpRequest({ host: url.hostname, port: url.port, path: "/mcp", headers: { Host: "attacker.example.com" } }, (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        })
          .on("error", reject)
          .end();
      });
      assert.equal(rebound, 421);
    } finally {
      await example.close();
    }
  });

  it("limits the token endpoint and the MCP route through the RateLimiter", async () => {
    const example = await start({ rateLimitPerMinute: 2 });
    try {
      const token = () => fetch(`${example.origin}/token`, form({ grant_type: "refresh_token", refresh_token: "x", client_id: CLIENT_ID }));
      assert.equal((await token()).status, 400);
      assert.equal((await token()).status, 400);
      const limited = await token();
      assert.equal(limited.status, 429);
      assert.equal(limited.headers.get("retry-after"), "60");
      const mcp = () => fetch(example.resource, { method: "POST", headers: { Authorization: "Bearer x" }, body: "{}" });
      assert.equal((await mcp()).status, 401);
      assert.equal((await mcp()).status, 401);
      assert.equal((await mcp()).status, 429);
    } finally {
      await example.close();
    }
  });

  it("npm start: main.ts serves on the port it is given", async () => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../src/main.ts", import.meta.url))], {
      env: { ...process.env, PORT: "0" },
      stdio: ["ignore", "pipe", "inherit"],
    });
    try {
      const resource = await new Promise<string>((resolve, reject) => {
        let out = "";
        child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
          out += chunk;
          const match = /MCP server: +(\S+)/.exec(out);
          if (match) resolve(match[1]!);
        });
        child.once("exit", (code) => reject(new Error(`main.ts exited (${code}): ${out}`)));
      });
      assert.match(resource, /^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
      const d = await discover(resource);
      assert.equal(d.tokenEndpoint, `${new URL(resource).origin}/token`);
      // It accepts the claudeClients preset's hosts only: this test's client is refused before any fetch.
      const url = new URL(d.authorizationEndpoint);
      url.search = new URLSearchParams({ response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }).toString();
      const refused = await fetch(url, { redirect: "manual" });
      assert.equal(refused.status, 400);
      assert.match(await refused.text(), /refused \(untrusted_client\)/);
    } finally {
      child.kill();
    }
  });

  it("with the default guarded fetch, an injected resolver cannot point the metadata fetch at loopback", async () => {
    const resolved: string[] = [];
    const example = await startExampleServer({
      port: 0,
      clients: CLIENTS,
      // The documented hook: it replaces DNS, and the SSRF guard still checks every address.
      clientMetadata: {
        resolveHost: async (hostname) => {
          resolved.push(hostname);
          return [{ address: "127.0.0.1", family: 4 }];
        },
      },
    });
    try {
      const d = await discover(example.resource);
      const hitsBefore = documentHits.length;
      const url = new URL(d.authorizationEndpoint);
      const { challenge } = pkce();
      url.search = new URLSearchParams({
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "s",
        resource: d.resource,
      }).toString();
      const refused = await fetch(url, { redirect: "manual" });
      assert.equal(refused.status, 400);
      assert.match(await refused.text(), /refused \(invalid_client\)/);
      assert.deepEqual(resolved, [CLIENT_HOST]);
      assert.equal(documentHits.length, hitsBefore, "nothing was fetched");
    } finally {
      await example.close();
    }
  });
});
