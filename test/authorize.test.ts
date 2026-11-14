import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { sameResource } from "../src/authorize.ts";
import { sha256Hex } from "../src/encoding.ts";
import type { KeyProvider } from "../src/keys.ts";
import type { CodeStore } from "../src/stores.ts";
import {
  authorizeParams,
  CHALLENGE,
  CLIENT_DOCUMENT,
  CLIENT_ID,
  clock,
  harness,
  HOSTED_REDIRECT,
  ISSUER,
  RESOURCE,
} from "./helpers.ts";

/** What the token endpoint would pass to take. */
const SPENT = { familyId: "f", ttlSeconds: 660 };
describe("checkAuthorizeRequest", () => {
  it("accepts a well-formed request and grants the default scopes when none is named", async () => {
    const h = await harness();
    const check = await h.fd.checkAuthorizeRequest(authorizeParams());
    assert.deepEqual(check, {
      ok: true,
      request: {
        clientId: CLIENT_ID,
        clientName: "Example Client",
        clientHost: "client.example.com",
        redirectUri: HOSTED_REDIRECT,
        redirectHost: "client.example.com",
        loopback: false,
        codeChallenge: CHALLENGE,
        state: "state-123",
        scopes: ["notes:read"],
        requestedScope: null,
      },
    });
  });

  it("grants named scopes in config order, and the defaults for offline_access alone", async () => {
    const h = await harness();
    const scopesOf = async (scope: string) => {
      const check = await h.fd.checkAuthorizeRequest(authorizeParams({ scope }));
      assert.ok(check.ok);
      return [check.request.scopes, check.request.requestedScope];
    };
    assert.deepEqual(await scopesOf("notes:write notes:read offline_access"), [["notes:read", "notes:write"], "notes:write notes:read offline_access"]);
    assert.deepEqual(await scopesOf("notes:write"), [["notes:write"], "notes:write"]);
    assert.deepEqual(await scopesOf("offline_access"), [["notes:read"], "offline_access"]);
  });

  it("accepts a native client's loopback redirect with an ephemeral port, and URLSearchParams input", async () => {
    const h = await harness();
    const params = new URLSearchParams(authorizeParams({ redirect_uri: "http://127.0.0.1:51234/callback" }));
    const check = await h.fd.checkAuthorizeRequest(params);
    assert.ok(check.ok);
    assert.equal(check.request.loopback, true);
    assert.equal(check.request.redirectHost, "127.0.0.1:51234");
  });

  it("accepts a resource parameter with an upper-case scheme or host, or a trailing slash at the root", async () => {
    assert.equal(sameResource("HTTPS://MCP.EXAMPLE.COM/mcp", RESOURCE), true);
    assert.equal(sameResource("https://mcp.example.com/", "https://mcp.example.com"), true);
    for (const bad of [
      "https://mcp.example.com/MCP",
      "https://mcp.example.com/mcp/",
      "https://mcp.example.com/mcp?x=1",
      "https://mcp.example.com/mcp?",
      "https://mcp.example.com/mcp#",
      "https://u@mcp.example.com/mcp",
      "https://u:p@mcp.example.com/mcp",
      "https://:p@mcp.example.com/mcp",
      "https://@mcp.example.com/mcp",
      "https://mcp.example.com:443/mcp",
      "https:\\\\mcp.example.com\\mcp",
      " https://mcp.example.com/mcp",
      "https://mcp.example.com/./mcp",
      "nope",
    ]) {
      assert.equal(sameResource(bad, RESOURCE), false, bad);
    }
  });

  describe("client and redirect failures are pages, never redirects", () => {
    const pages: [string, Record<string, string | undefined>, string][] = [
      ["no client_id", { client_id: undefined }, "invalid_client"],
      ["an empty client_id", { client_id: "" }, "invalid_client"],
      ["a client on another host", { client_id: "https://evil.example.net/m.json" }, "untrusted_client"],
      ["an http client_id", { client_id: "http://client.example.com/oauth/metadata.json" }, "untrusted_client"],
      ["an allowed host with a bad URL shape", { client_id: "https://client.example.com/m.json?x=1" }, "invalid_client"],
      ["no redirect_uri", { redirect_uri: undefined }, "invalid_redirect"],
      ["an unregistered redirect_uri", { redirect_uri: "https://client.example.com/other" }, "invalid_redirect"],
      ["a loopback redirect on another host", { redirect_uri: "http://localhost:5/callback" }, "invalid_redirect"],
    ];
    for (const [what, change, error] of pages) {
      it(`${what}: ${error}`, async () => {
        const h = await harness();
        assert.deepEqual(await h.fd.checkAuthorizeRequest(authorizeParams(change)), { ok: false, kind: "page", error });
      });
    }

    it("an untrusted host is refused before anything is fetched", async () => {
      const h = await harness();
      await h.fd.checkAuthorizeRequest(authorizeParams({ client_id: "https://evil.example.net/m.json" }));
      assert.equal(h.fetches.length, 0);
    });

    it("a document that does not validate is invalid_client", async () => {
      const h = await harness({}, { document: { ...CLIENT_DOCUMENT, client_secret: "x" } });
      assert.deepEqual(await h.fd.checkAuthorizeRequest(authorizeParams()), { ok: false, kind: "page", error: "invalid_client" });
    });

    it("a repeated client_id or redirect_uri is refused as a page", async () => {
      const h = await harness();
      const repeated = new URLSearchParams(authorizeParams());
      repeated.append("client_id", CLIENT_ID);
      assert.deepEqual(await h.fd.checkAuthorizeRequest(repeated), { ok: false, kind: "page", error: "invalid_client" });
      assert.deepEqual(await h.fd.checkAuthorizeRequest({ ...authorizeParams(), redirect_uri: [HOSTED_REDIRECT, HOSTED_REDIRECT] }), {
        ok: false,
        kind: "page",
        error: "invalid_redirect",
      });
    });
  });

  describe("once the redirect is verified, failures go back to it with state and iss", () => {
    const redirects: [string, Record<string, string | undefined>, string, boolean][] = [
      ["response_type token", { response_type: "token" }, "unsupported_response_type", true],
      ["no response_type", { response_type: undefined }, "unsupported_response_type", true],
      ["plain PKCE", { code_challenge_method: "plain" }, "invalid_request", true],
      ["no challenge", { code_challenge: undefined }, "invalid_request", true],
      ["a malformed challenge", { code_challenge: "short" }, "invalid_request", true],
      ["no state", { state: undefined }, "invalid_request", false],
      ["a state over 512 characters", { state: "s".repeat(513) }, "invalid_request", false],
      ["no resource", { resource: undefined }, "invalid_request", true],
      ["another resource", { resource: "https://other.example.com/mcp" }, "invalid_target", true],
      ["an unknown scope", { scope: "notes:read notes:admin" }, "invalid_scope", true],
      ["an empty scope", { scope: "" }, "invalid_scope", true],
      ["a blank scope", { scope: "   " }, "invalid_scope", true],
    ];
    for (const [what, change, error, hasState] of redirects) {
      it(`${what}: ${error}`, async () => {
        const h = await harness();
        const check = await h.fd.checkAuthorizeRequest(authorizeParams(change));
        assert.ok(!check.ok && check.kind === "redirect");
        assert.equal(check.error, error);
        const url = new URL(check.redirectUrl);
        assert.equal(`${url.origin}${url.pathname}`, HOSTED_REDIRECT);
        assert.equal(url.searchParams.get("error"), error);
        assert.equal(url.searchParams.get("iss"), ISSUER);
        assert.equal(url.searchParams.get("state"), hasState ? "state-123" : null);
      });
    }
  });
});

describe("approve", () => {
  it("re-checks the request, stores a hash of a single-use code bound to everything consented, and redirects with code, state and iss", async () => {
    const h = await harness();
    const result = await h.fd.approve({ params: authorizeParams({ scope: "notes:read notes:write" }), subject: "user-1", context: { tenant: "t-1" } });
    assert.ok(result.ok);
    const url = new URL(result.redirectUrl);
    assert.equal(url.searchParams.get("state"), "state-123");
    assert.equal(url.searchParams.get("iss"), ISSUER);
    const code = url.searchParams.get("code")!;
    assert.match(code, /^[A-Za-z0-9_-]{43}$/);
    const record = await h.codes.take(sha256Hex(code), SPENT);
    assert.deepEqual(record, {
      subject: "user-1",
      clientId: CLIENT_ID,
      redirectUri: HOSTED_REDIRECT,
      codeChallenge: CHALLENGE,
      scopes: ["notes:read", "notes:write"],
      context: { tenant: "t-1" },
      authorizedAt: h.clock.now(),
      expiresAt: h.clock.now() + 60_000,
    });
    assert.equal(await h.codes.take(code, SPENT), null, "the store never holds the code itself");
    assert.deepEqual(h.events, [{ type: "code.issued", subject: "user-1", clientId: CLIENT_ID, scopes: ["notes:read", "notes:write"] }]);
  });

  it("keeps a query the registered redirect already carries", async () => {
    const withQuery = "https://client.example.com/callback?tenant=a";
    const h = await harness({ redirectUris: [withQuery] }, { document: { ...CLIENT_DOCUMENT, redirect_uris: [withQuery] } });
    const result = await h.fd.approve({ params: authorizeParams({ redirect_uri: withQuery }), subject: "user-1" });
    assert.ok(result.ok);
    assert.equal(new URL(result.redirectUrl).searchParams.get("tenant"), "a");
  });

  it("narrows to the scopes the host passes, and refuses widening, empty or malformed input", async () => {
    const h = await harness();
    const params = authorizeParams({ scope: "notes:read notes:write" });
    const narrowed = await h.fd.approve({ params, subject: "user-1", scopes: ["notes:write"] });
    assert.ok(narrowed.ok);
    const record = await h.codes.take(sha256Hex(new URL(narrowed.redirectUrl).searchParams.get("code")!), SPENT);
    assert.deepEqual(record?.scopes, ["notes:write"]);
    await assert.rejects(h.fd.approve({ params: authorizeParams(), subject: "user-1", scopes: ["notes:write"] }), TypeError);
    await assert.rejects(h.fd.approve({ params, subject: "user-1", scopes: [] }), TypeError);
    await assert.rejects(h.fd.approve({ params, subject: "" }), TypeError);
    await assert.rejects(h.fd.approve({ params, subject: "user-1", context: { n: 1 as never } }), TypeError);
  });

  it("returns the check's refusal unchanged", async () => {
    const h = await harness();
    assert.deepEqual(await h.fd.approve({ params: authorizeParams({ client_id: "https://evil.example.net/x" }), subject: "u" }), {
      ok: false,
      kind: "page",
      error: "untrusted_client",
    });
  });

  it("mints no code when there is no signing key, or the key provider throws", async () => {
    const puts: string[] = [];
    const codeStore: CodeStore = {
      put: async (hash) => void puts.push(hash),
      take: async () => null,
      markReplayed: async () => null,
      wasReplayed: async () => false,
    };
    const none: KeyProvider = { signingKey: async () => null, verificationKey: async () => null };
    const h = await harness({ keys: none, codeStore });
    assert.deepEqual(await h.fd.approve({ params: authorizeParams(), subject: "u" }), { ok: false, kind: "unavailable" });
    const throws: KeyProvider = { signingKey: () => Promise.reject(new Error("kms down")), verificationKey: async () => null };
    const t = await harness({ keys: throws, codeStore });
    assert.deepEqual(await t.fd.approve({ params: authorizeParams(), subject: "u" }), { ok: false, kind: "unavailable" });
    assert.equal(t.reports[0]?.where, "keys.signingKey");
    assert.deepEqual(puts, [], "no code was stored");
    assert.deepEqual([...h.events, ...t.events], [], "no code was issued");
  });

  it("a clock that throws fails closed: no code, reported, never a throw out of approve", async () => {
    const time = clock();
    let calls = 0;
    let failFrom = Infinity;
    const flaky = {
      now: () => {
        calls += 1;
        if (calls >= failFrom) throw new Error("clock down");
        return time.now();
      },
      advance: time.advance,
    };
    const h = await harness({}, { clock: flaky });
    // How many times the check alone reads the clock, so the next read is the issuance's.
    calls = 0;
    assert.ok((await h.fd.checkAuthorizeRequest(authorizeParams())).ok);
    const checkReads = calls;

    calls = 0;
    failFrom = checkReads + 1;
    assert.deepEqual(await h.fd.approve({ params: authorizeParams(), subject: "u" }), { ok: false, kind: "unavailable" });
    assert.equal(h.reports.at(-1)?.where, "now");

    // A clock that fails during the check as well.
    calls = 0;
    failFrom = 1;
    assert.deepEqual(await h.fd.approve({ params: authorizeParams(), subject: "u" }), { ok: false, kind: "unavailable" });
    assert.equal(h.reports.at(-1)?.where, "approve");
    assert.ok(!h.events.some((e) => e.type === "code.issued"), "no code was issued");
  });

  it("hands out nothing when the code store write fails (safety property 3)", async () => {
    const h = await harness({
      codeStore: { put: () => Promise.reject(new Error("write failed")), take: async () => null, markReplayed: async () => null, wasReplayed: async () => false },
    });
    assert.deepEqual(await h.fd.approve({ params: authorizeParams(), subject: "u" }), { ok: false, kind: "unavailable" });
    assert.equal(h.reports[0]?.where, "codeStore.put");
    assert.equal(h.events.length, 0);
  });

  it("wraps the code it hands out and stores the hash of the bare value (safety property 6)", async () => {
    const h = await harness({
      tokenWrapper: { wrap: (kind, value) => `${kind}.east.${value}`, unwrap: () => null },
    });
    const result = await h.fd.approve({ params: authorizeParams(), subject: "u" });
    assert.ok(result.ok);
    const code = new URL(result.redirectUrl).searchParams.get("code")!;
    assert.match(code, /^code\.east\./);
    assert.ok(await h.codes.take(sha256Hex(code.slice("code.east.".length)), SPENT));
  });
});

describe("denialUrl", () => {
  it("sends access_denied with state and iss to the verified redirect", async () => {
    const h = await harness();
    const check = await h.fd.checkAuthorizeRequest(authorizeParams());
    assert.ok(check.ok);
    const url = new URL(h.fd.denialUrl(check.request));
    assert.deepEqual(Object.fromEntries(url.searchParams), { error: "access_denied", state: "state-123", iss: ISSUER });
  });
});
