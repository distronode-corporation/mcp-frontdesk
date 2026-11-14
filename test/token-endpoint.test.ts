import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { decodeJwt } from "jose";

import { sha256Hex } from "../src/encoding.ts";
import type { KeyProvider } from "../src/keys.ts";
import type { CodeStore, GrantStore } from "../src/stores.ts";
import {
  approveCode,
  authorizeParams,
  CLIENT_ID,
  codeForm,
  connect,
  harness,
  HOSTED_REDIRECT,
  ISSUER,
  refreshForm,
  RESOURCE,
  resourceRequest,
  tokenRequest,
  type Harness,
  type TokenBody,
} from "./helpers.ts";

async function post(h: Harness, form: Record<string, string>, headers: Record<string, string> = {}) {
  const res = await h.fd.handleToken(tokenRequest(form, headers));
  return { status: res.status, headers: res.headers, body: (await res.json()) as TokenBody };
}

const INVALID_GRANT = { status: 400, body: { error: "invalid_grant" } };
const slim = (r: { status: number; body: unknown }) => ({ status: r.status, body: r.body });

describe("token endpoint: authorization_code", () => {
  it("exchanges a code for a Bearer access token and a refresh token, no-store", async () => {
    const h = await harness();
    const code = await approveCode(h, { context: { tenant: "t-1" } });
    const res = await post(h, codeForm(code));
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("pragma"), "no-cache");
    assert.equal(res.body.token_type, "Bearer");
    assert.equal(res.body.expires_in, 600);
    assert.equal(res.body.scope, "notes:read");
    assert.match(res.body.refresh_token, /^[A-Za-z0-9_-]{43}$/);
    const claims = decodeJwt(res.body.access_token);
    assert.equal(claims.sub, "user-1");
    assert.equal(claims.client_id, CLIENT_ID);
    assert.equal(claims.email, undefined);
    assert.deepEqual(
      h.events.map((e) => e.type),
      ["code.issued", "grant.created"],
    );
  });

  it("spends a code exactly once", async () => {
    const h = await harness();
    const code = await approveCode(h);
    assert.equal((await post(h, codeForm(code))).status, 200);
    assert.deepEqual(slim(await post(h, codeForm(code))), INVALID_GRANT);
  });

  it("every refusal of a code is the same invalid_grant, and the reason goes to the audit sink only (safety property 3)", async () => {
    const cases: [string, (code: string) => Record<string, string>, string][] = [
      ["an unknown code", () => codeForm("never-issued"), "unknown"],
      ["another client", (c) => codeForm(c, { client_id: "https://client.example.com/other.json" }), "client_mismatch"],
      ["another redirect", (c) => codeForm(c, { redirect_uri: "http://127.0.0.1/callback" }), "redirect_mismatch"],
      ["a wrong verifier", (c) => codeForm(c, { code_verifier: "x".repeat(43) }), "pkce_mismatch"],
      ["a malformed verifier", (c) => codeForm(c, { code_verifier: "short" }), "malformed_verifier"],
    ];
    const bodies = new Set<string>();
    for (const [what, form, reason] of cases) {
      const h = await harness();
      const code = await approveCode(h);
      const res = await h.fd.handleToken(tokenRequest(form(code)));
      assert.equal(res.status, 400, what);
      bodies.add(await res.text());
      assert.deepEqual(h.events.at(-1), { type: "token.refused", grantType: "authorization_code", reason }, what);
    }
    assert.deepEqual([...bodies], ['{"error":"invalid_grant"}']);
  });

  it("burns the code on the first attempt, even a wrong one", async () => {
    const h = await harness();
    const code = await approveCode(h);
    assert.deepEqual(slim(await post(h, codeForm(code, { code_verifier: "y".repeat(43) }))), INVALID_GRANT);
    assert.deepEqual(slim(await post(h, codeForm(code))), INVALID_GRANT);
  });

  it("a malformed verifier does not burn a good code", async () => {
    const h = await harness();
    const code = await approveCode(h);
    assert.deepEqual(slim(await post(h, codeForm(code, { code_verifier: "short" }))), INVALID_GRANT);
    assert.equal((await post(h, codeForm(code))).status, 200);
  });

  it("refuses an expired code even if the store still returns it", async () => {
    const h = await harness();
    const code = await approveCode(h);
    const record = await h.codes.take(sha256Hex(code));
    const stale: CodeStore = { put: async () => undefined, take: async () => ({ ...record!, expiresAt: h.clock.now() }) };
    const s = await harness({ codeStore: stale }, { clock: h.clock });
    assert.deepEqual(slim(await post(s, codeForm(code))), INVALID_GRANT);
    assert.equal((s.events.at(-1) as { reason: string }).reason, "expired");
  });

  it("a code store that throws is a refusal, never a token (safety property 3)", async () => {
    const h = await harness();
    const code = await approveCode(h);
    const broken: CodeStore = { put: async () => undefined, take: () => Promise.reject(new Error("store down")) };
    const s = await harness({ codeStore: broken });
    assert.deepEqual(slim(await post(s, codeForm(code))), INVALID_GRANT);
    assert.equal(s.reports[0]?.where, "codeStore.take");
  });

  it("asks isGrantActive before issuing, and refuses when it says no or throws", async () => {
    const seen: unknown[] = [];
    const h = await harness({ isGrantActive: (g) => (seen.push(g), false) });
    const code = await approveCode(h, { context: { tenant: "t-9" } });
    assert.deepEqual(slim(await post(h, codeForm(code))), INVALID_GRANT);
    assert.deepEqual(seen, [
      { subject: "user-1", clientId: CLIENT_ID, scopes: ["notes:read"], context: { tenant: "t-9" }, familyId: null, authorizedAt: new Date(h.clock.now()) },
    ]);
    const t = await harness({ isGrantActive: () => Promise.reject(new Error("db down")) });
    assert.deepEqual(slim(await post(t, codeForm(await approveCode(t)))), INVALID_GRANT);
    assert.equal(t.reports[0]?.where, "isGrantActive");
  });

  it("carries the consent time in the code: authorizedAt is when the person approved, not when the code was redeemed", async () => {
    const seen: Date[] = [];
    const h = await harness({ isGrantActive: (g) => (seen.push(g.authorizedAt), true) });
    const approvedAt = h.clock.now();
    const code = await approveCode(h);
    h.clock.advance(30_000);
    assert.equal((await post(h, codeForm(code))).status, 200);
    assert.deepEqual(seen, [new Date(approvedAt)]);
    const [summary] = await h.fd.listGrants("user-1");
    assert.equal(summary?.authorizedAt.getTime(), approvedAt);
    assert.equal(summary?.lastRefreshedAt.getTime(), approvedAt + 30_000);
  });

  it("checks the resource parameter, and accepts its absence", async () => {
    const h = await harness();
    assert.deepEqual(slim(await post(h, codeForm(await approveCode(h), { resource: "https://other.example.com" }))), {
      status: 400,
      body: { error: "invalid_target" },
    });
    assert.equal((await post(h, codeForm(await approveCode(h), { resource: undefined }))).status, 200);
  });

  it("refuses a code request missing a parameter as invalid_request", async () => {
    const h = await harness();
    for (const name of ["code", "code_verifier", "redirect_uri"]) {
      assert.deepEqual(slim(await post(h, codeForm("c", { [name]: undefined }))), { status: 400, body: { error: "invalid_request" } }, name);
    }
  });

  it("adds custom claims from the hook (an email when the host wants one, safety property 5)", async () => {
    const h = await harness({ accessTokenClaims: (g) => ({ email: `${g.subject}@example.com`, tenant: g.context.tenant ?? "" }) });
    const body = await connect(h, { context: { tenant: "t-1" } });
    const claims = decodeJwt(body.access_token);
    assert.equal(claims.email, "user-1@example.com");
    assert.equal(claims.tenant, "t-1");
  });

  it("a hook that sets a registered claim is a server error, reported", async () => {
    const h = await harness({ accessTokenClaims: () => ({ sub: "someone-else" }) });
    const code = await approveCode(h);
    assert.deepEqual(slim(await post(h, codeForm(code))), { status: 500, body: { error: "server_error" } });
    assert.equal(h.reports[0]?.where, "tokenEndpoint");
  });

  it("unwraps a wrapped code, and refuses one the wrapper does not recognise without a lookup (safety property 6)", async () => {
    let takes = 0;
    const h = await harness({
      tokenWrapper: {
        wrap: (_kind, value) => `east.${value}`,
        unwrap: (_kind, presented) => (presented.startsWith("east.") ? presented.slice(5) : null),
      },
    });
    const take = h.codes.take.bind(h.codes);
    h.codes.take = async (hash) => (takes++, take(hash));
    const code = await approveCode(h);
    assert.deepEqual(slim(await post(h, codeForm(`west.${code.slice(5)}`))), INVALID_GRANT);
    assert.equal(takes, 0);
    const ok = await post(h, codeForm(code));
    assert.equal(ok.status, 200);
    assert.match(ok.body.refresh_token, /^east\./);
  });
});

describe("token endpoint: the request itself", () => {
  it("refuses another method, a non-form body, a repeated parameter and an oversized body", async () => {
    const h = await harness();
    const get = await h.fd.handleToken(tokenRequest({}, {}, "GET"));
    assert.equal(get.status, 405);
    assert.equal(get.headers.get("allow"), "POST, OPTIONS");
    const json = new Request(`${ISSUER}/token`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    assert.deepEqual(await (await h.fd.handleToken(json)).json(), { error: "invalid_request" });
    const untyped = new Request(`${ISSUER}/token`, { method: "POST", body: new Uint8Array([1]) });
    assert.deepEqual(await (await h.fd.handleToken(untyped)).json(), { error: "invalid_request" });
    const repeated = new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" },
      body: "grant_type=refresh_token&client_id=a&client_id=b&refresh_token=x",
    });
    assert.deepEqual(await (await h.fd.handleToken(repeated)).json(), { error: "invalid_request" });
    const big = tokenRequest({ grant_type: "refresh_token", client_id: CLIENT_ID, refresh_token: "x".repeat(9000) });
    assert.deepEqual(await (await h.fd.handleToken(big)).json(), { error: "invalid_request" });
  });

  it("stops reading an endless body at 8 KB (safety property 2)", async () => {
    const h = await harness();
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          pulled += 1;
          controller.enqueue(new Uint8Array(1024).fill(97));
        },
      },
      { highWaterMark: 0 },
    );
    const req = new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      duplex: "half",
    } as RequestInit);
    assert.deepEqual(await (await h.fd.handleToken(req)).json(), { error: "invalid_request" });
    assert.ok(pulled <= 10, `pulled ${pulled} chunks`);
  });

  it("refuses a missing client_id, a client secret and an Authorization header", async () => {
    const h = await harness();
    for (const [form, headers] of [
      [refreshForm("x", { client_id: undefined }), {}],
      [refreshForm("x", { client_secret: "s" }), {}],
      [refreshForm("x"), { Authorization: "Basic YTpi" }],
    ] as const) {
      assert.deepEqual(slim(await post(h, form, headers)), { status: 400, body: { error: "invalid_request" } });
    }
  });

  it("refuses unknown and missing grant types", async () => {
    const h = await harness();
    assert.deepEqual((await post(h, { grant_type: "client_credentials", client_id: CLIENT_ID })).body, { error: "unsupported_grant_type" });
    assert.deepEqual((await post(h, { client_id: CLIENT_ID })).body, { error: "invalid_request" });
  });

  it("answers temporarily_unavailable before spending anything when there is no signing key", async () => {
    const h = await harness();
    const code = await approveCode(h);
    let keyThere = false;
    const real = h.keys;
    const flaky: KeyProvider = { signingKey: async () => (keyThere ? real.signingKey() : null), verificationKey: (kid) => real.verificationKey(kid) };
    const s = await harness({ keys: flaky, codeStore: h.codes }, { clock: h.clock });
    assert.deepEqual(slim(await post(s, codeForm(code))), { status: 503, body: { error: "temporarily_unavailable" } });
    keyThere = true;
    assert.equal((await post(s, codeForm(code))).status, 200, "the code survived the refusal");
  });

  it("a key provider that throws is temporarily_unavailable", async () => {
    const h = await harness({ keys: { signingKey: () => Promise.reject(new Error("kms")), verificationKey: async () => null } });
    assert.deepEqual(slim(await post(h, refreshForm("x"))), { status: 503, body: { error: "temporarily_unavailable" } });
    assert.equal(h.reports[0]?.where, "keys.signingKey");
  });

  it("asks for the key once per request and signs with it, so a key that vanishes after the check cannot burn the code", async () => {
    const real = (await harness()).keys;
    let calls = 0;
    const vanishing: KeyProvider = { signingKey: async () => (++calls === 1 ? real.signingKey() : null), verificationKey: real.verificationKey };
    const v = await harness({ keys: vanishing });
    const code = await approveCode(v);
    calls = 0;
    const exchanged = await post(v, codeForm(code));
    assert.equal(exchanged.status, 200);
    assert.equal(calls, 1);
    calls = 0;
    const refreshed = await post(v, refreshForm(exchanged.body.refresh_token));
    assert.equal(refreshed.status, 200);
    assert.equal(calls, 1);
    assert.ok((await v.fd.authenticate(resourceRequest(refreshed.body.access_token))).ok);
  });

  it("a grant store that throws is a server error, so the client retries instead of dropping the connection", async () => {
    const h = await harness();
    const broken = h.grants as GrantStore;
    broken.findByTokenHash = () => Promise.reject(new Error("db down"));
    assert.deepEqual(slim(await post(h, refreshForm("x"))), { status: 500, body: { error: "server_error" } });
    assert.equal(h.reports[0]?.where, "tokenEndpoint");
  });

  it("consults the rate limiter (safety property 7)", async () => {
    let allow = false;
    const seen: string[] = [];
    const h = await harness({ rateLimiter: { allow: (endpoint) => (seen.push(endpoint), allow) } });
    const res = await h.fd.handleToken(tokenRequest(refreshForm("x")));
    assert.equal(res.status, 429);
    assert.equal(res.headers.get("retry-after"), "60");
    assert.deepEqual(await res.json(), { error: "slow_down" });
    allow = true;
    assert.equal((await post(h, refreshForm("x"))).status, 400);
    assert.deepEqual(seen, ["token", "token"]);
  });

  it("a rate limiter that throws fails closed: reported, and a server error before anything is read", async () => {
    const h = await harness({ rateLimiter: { allow: () => Promise.reject(new Error("limiter backend down")) } });
    const code = await approveCode(h);
    assert.deepEqual(slim(await post(h, codeForm(code))), { status: 500, body: { error: "server_error" } });
    assert.equal(h.reports.at(-1)?.where, "tokenEndpoint");
    assert.ok(await h.codes.take(sha256Hex(code)), "the code was not touched");
  });

  it("answers CORS for an allowed origin, and refuses any other origin", async () => {
    const h = await harness();
    const allowed = await h.fd.handleToken(tokenRequest(refreshForm("x"), { Origin: "https://app.example.com" }));
    assert.equal(allowed.headers.get("access-control-allow-origin"), "https://app.example.com");
    assert.equal(allowed.headers.get("vary"), "Origin");
    const preflight = await h.fd.handleToken(new Request(`${ISSUER}/token`, { method: "OPTIONS", headers: { Origin: "https://app.example.com" } }));
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-methods"), "POST");
    assert.equal(preflight.headers.get("cache-control"), "no-store");
    assert.equal(preflight.headers.get("pragma"), "no-cache");
    const evil = await h.fd.handleToken(tokenRequest(refreshForm("x"), { Origin: "https://evil.example.net" }));
    assert.equal(evil.status, 403);
    assert.equal(evil.headers.get("access-control-allow-origin"), null);
    const none = await h.fd.handleToken(tokenRequest(refreshForm("x")));
    assert.equal(none.headers.get("access-control-allow-origin"), null);
  });
});

describe("token endpoint: refresh_token (safety property 4)", () => {
  it("rotates: a new refresh token in the same family, the binding carried over", async () => {
    const h = await harness({ accessTokenClaims: (g) => ({ tenant: g.context.tenant ?? "" }) });
    const first = await connect(h, { context: { tenant: "t-1" } });
    h.clock.advance(60_000);
    const second = await post(h, refreshForm(first.refresh_token));
    assert.equal(second.status, 200);
    assert.notEqual(second.body.refresh_token, first.refresh_token);
    assert.equal(decodeJwt(second.body.access_token).tenant, "t-1");
    const [summary] = await h.fd.listGrants("user-1");
    assert.equal(summary?.lastRefreshedAt.getTime(), h.clock.now());
    assert.equal(summary?.authorizedAt.getTime(), h.clock.now() - 60_000);
    assert.equal(h.events.at(-1)?.type, "grant.refreshed");
  });

  it("reuse of a rotated token revokes the whole family, successor included, by default", async () => {
    const h = await harness();
    const first = await connect(h);
    const second = await post(h, refreshForm(first.refresh_token));
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token))), INVALID_GRANT);
    assert.deepEqual(slim(await post(h, refreshForm(second.body.refresh_token))), INVALID_GRANT);
    assert.deepEqual(await h.fd.listGrants("user-1"), []);
    assert.ok(h.events.some((e) => e.type === "grant.revoked" && e.reason === "reuse"));
  });

  it('with refreshTokenReuse "refuse", reuse is refused and the successor lives', async () => {
    const h = await harness({ refreshTokenReuse: "refuse" });
    const first = await connect(h);
    const second = await post(h, refreshForm(first.refresh_token));
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token))), INVALID_GRANT);
    assert.equal((await post(h, refreshForm(second.body.refresh_token))).status, 200);
    assert.ok(!h.events.some((e) => e.type === "grant.revoked"));
  });

  it("two concurrent refreshes of one token: one wins and the race counts as reuse", async () => {
    const h = await harness();
    const first = await connect(h);
    const results = await Promise.all([post(h, refreshForm(first.refresh_token)), post(h, refreshForm(first.refresh_token))]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
    const winner = results.find((r) => r.status === 200)!;
    assert.deepEqual(slim(await post(h, refreshForm(winner.body.refresh_token))), INVALID_GRANT, "the family is revoked");

    const r = await harness({ refreshTokenReuse: "refuse" });
    const t = await connect(r);
    const raced = await Promise.all([post(r, refreshForm(t.refresh_token)), post(r, refreshForm(t.refresh_token))]);
    const won = raced.find((x) => x.status === 200)!;
    assert.equal((await post(r, refreshForm(won.body.refresh_token))).status, 200, "the winner's successor lives");
  });

  it("a concurrent refresh that loses the claim to a revocation leaves nothing live", async () => {
    const h = await harness();
    const first = await connect(h);
    const rotate = h.grants.rotate.bind(h.grants);
    h.grants.rotate = async (id, now, successor) => {
      await h.grants.revokeFamily(successor.familyId, now);
      return rotate(id, now, successor);
    };
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token))), INVALID_GRANT);
    assert.equal((h.events.at(-1) as { reason: string }).reason, "revoked");
    assert.deepEqual(await h.fd.listGrants("user-1"), []);
  });

  it("another client presenting the token revokes the family, whatever the reuse policy", async () => {
    const h = await harness({ refreshTokenReuse: "refuse" });
    const first = await connect(h);
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token, { client_id: "https://client.example.com/other.json" }))), INVALID_GRANT);
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token))), INVALID_GRANT);
    assert.ok(h.events.some((e) => e.type === "grant.revoked" && e.reason === "client_mismatch"));
  });

  it("a grant isGrantActive now refuses is revoked before any rotation", async () => {
    let active = true;
    const h = await harness({ isGrantActive: () => active });
    const first = await connect(h);
    active = false;
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token))), INVALID_GRANT);
    active = true;
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token))), INVALID_GRANT);
    assert.ok(h.events.some((e) => e.type === "grant.revoked" && e.reason === "inactive"));
  });

  it("refuses an unknown, a revoked and an expired token with the same invalid_grant", async () => {
    const h = await harness();
    assert.deepEqual(slim(await post(h, refreshForm("never-issued"))), INVALID_GRANT);
    const revoked = await connect(h);
    const [grant] = await h.fd.listGrants("user-1");
    await h.fd.revokeGrant("user-1", grant!.familyId);
    assert.deepEqual(slim(await post(h, refreshForm(revoked.refresh_token))), INVALID_GRANT);
    const expiring = await connect(h);
    h.clock.advance(30 * 86_400_000);
    assert.deepEqual(slim(await post(h, refreshForm(expiring.refresh_token))), INVALID_GRANT);
    assert.deepEqual(
      h.events.filter((e) => e.type === "token.refused").map((e) => (e as { reason: string }).reason),
      ["unknown", "revoked", "expired"],
    );
  });

  it("refuses a refresh token the wrapper does not recognise without a lookup", async () => {
    const h = await harness({ tokenWrapper: { wrap: (_k, v) => `east.${v}`, unwrap: (_k, p) => (p.startsWith("east.") ? p.slice(5) : null) } });
    const first = await connect(h);
    let finds = 0;
    const find = h.grants.findByTokenHash.bind(h.grants);
    h.grants.findByTokenHash = async (hash) => (finds++, find(hash));
    assert.deepEqual(slim(await post(h, refreshForm(`west.${first.refresh_token.slice(5)}`))), INVALID_GRANT);
    assert.equal(finds, 0);
    assert.equal((await post(h, refreshForm(first.refresh_token))).status, 200);
  });

  it("checks scope and resource before rotating, and never widens the grant", async () => {
    const h = await harness();
    const first = await connect(h);
    for (const scope of ["notes:admin", "", "  "]) {
      assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token, { scope }))), { status: 400, body: { error: "invalid_scope" } }, scope);
    }
    assert.deepEqual(slim(await post(h, refreshForm(first.refresh_token, { resource: "https://other.example.com" }))), {
      status: 400,
      body: { error: "invalid_target" },
    });
    const widened = await post(h, refreshForm(first.refresh_token, { scope: "notes:read notes:write offline_access", resource: RESOURCE }));
    assert.equal(widened.status, 200, "the refusals above did not cost the token");
    assert.equal(widened.body.scope, "notes:read");
  });

  it("refuses a refresh with no refresh_token", async () => {
    const h = await harness();
    assert.deepEqual(slim(await post(h, refreshForm("", { refresh_token: undefined }))), { status: 400, body: { error: "invalid_request" } });
  });
});

describe("grants listing and revocation", () => {
  it("lists the subject's own live connections and revokes only their own", async () => {
    const h = await harness();
    await connect(h, { context: { tenant: "t-1" } });
    await connect(h, { subject: "user-2" });
    const mine = await h.fd.listGrants("user-1");
    assert.equal(mine.length, 1);
    assert.equal(mine[0]?.clientId, CLIENT_ID);
    assert.deepEqual(mine[0]?.context, { tenant: "t-1" });
    assert.equal(await h.fd.revokeGrant("user-2", mine[0]!.familyId), false);
    assert.equal((await h.fd.listGrants("user-1")).length, 1);
    assert.equal(await h.fd.revokeGrant("user-1", mine[0]!.familyId), true);
    assert.equal(await h.fd.revokeGrant("user-1", mine[0]!.familyId), false);
    assert.deepEqual(await h.fd.listGrants("user-1"), []);
    assert.deepEqual(h.events.at(-1), { type: "grant.revoked", subject: "user-1", clientId: CLIENT_ID, familyId: mine[0]!.familyId, reason: "user" });
  });

  it("a revoke that finds no listed head still revokes, without an audit event", async () => {
    const h = await harness();
    const first = await connect(h);
    const [grant] = await h.fd.listGrants("user-1");
    h.clock.advance(31 * 86_400_000); // expired: no longer listed, still revocable
    const before = h.events.length;
    assert.equal(await h.fd.revokeGrant("user-1", grant!.familyId), true);
    assert.equal(h.events.length, before);
    assert.ok(first);
  });
});

describe("hooks that fail never change an answer", () => {
  it("a throwing audit sink is reported, and a throwing reporter is swallowed", async () => {
    const reports: string[] = [];
    const h = await harness({
      audit: { record: () => Promise.reject(new Error("sink down")) },
      reporter: { error: (where) => reports.push(where) },
    });
    assert.equal((await connect(h)).token_type, "Bearer");
    assert.deepEqual(reports, ["audit", "audit"]);
    const quiet = await harness({
      audit: {
        record: () => {
          throw new Error("sink down");
        },
      },
      reporter: {
        error: () => {
          throw new Error("reporter down");
        },
      },
    });
    assert.equal((await connect(quiet)).token_type, "Bearer");
  });

  it("works with no reporter, audit sink or rate limiter at all", async () => {
    const h = await harness({ reporter: undefined, audit: undefined, rateLimiter: undefined });
    const first = await connect(h);
    assert.equal((await post(h, refreshForm(first.refresh_token))).status, 200);
    assert.equal(HOSTED_REDIRECT.length > 0, true);
  });
});

describe("a scope removed from the config, and a mint that fails", () => {
  /** A second instance over the same stores, key and clock: the same server restarted with a new config. */
  async function restartedWith(h: Harness, overrides: Parameters<typeof harness>[0]) {
    return harness({ grantStore: h.grants, codeStore: h.codes, keys: h.keys, ...overrides }, { clock: h.clock });
  }

  it("a refresh narrows the grant to the scopes still configured, and says so in `scope`", async () => {
    const h = await harness();
    const first = await connect(h, { params: authorizeParams({ scope: "notes:read notes:write" }) });
    assert.equal(first.scope, "notes:read notes:write");

    const s = await restartedWith(h, { scopes: ["notes:read"] });
    const second = await post(s, refreshForm(first.refresh_token));
    assert.equal(second.status, 200);
    assert.equal(second.body.scope, "notes:read");
    assert.equal(decodeJwt(second.body.access_token).scope, "notes:read");
    assert.ok(await s.fd.authenticate(resourceRequest(second.body.access_token)).then((r) => r.ok));
    // The successor is narrowed for good: the removed scope does not come back without a new consent.
    assert.deepEqual((await s.fd.listGrants("user-1"))[0]?.scopes, ["notes:read"]);
    const third = await post(h, refreshForm(second.body.refresh_token));
    assert.equal(third.body.scope, "notes:read");
  });

  it("a refresh of a grant whose every scope was removed is refused and revokes the family, before any rotation", async () => {
    const h = await harness();
    const first = await connect(h);
    assert.equal(first.scope, "notes:read");

    const s = await restartedWith(h, { scopes: ["notes:write"], defaultScopes: ["notes:write"] });
    assert.deepEqual(slim(await post(s, refreshForm(first.refresh_token))), INVALID_GRANT);
    assert.ok(s.events.some((e) => e.type === "token.refused" && e.reason === "no_scope"));
    assert.ok(s.events.some((e) => e.type === "grant.revoked" && e.reason === "no_scope"));
    assert.deepEqual(await h.fd.listGrants("user-1"), []);
    assert.equal(s.reports.length, 0, "a refusal, not a crash");
  });

  it("a code approved before a scope was removed is exchanged for the scopes still configured", async () => {
    const h = await harness();
    const both = await approveCode(h, {}, authorizeParams({ scope: "notes:read notes:write" }));
    const only = await approveCode(h, {}, authorizeParams({ scope: "notes:write" }));

    const s = await restartedWith(h, { scopes: ["notes:read"], defaultScopes: ["notes:read"] });
    const narrowed = await post(s, codeForm(both));
    assert.equal(narrowed.status, 200);
    assert.equal(narrowed.body.scope, "notes:read");

    assert.deepEqual(slim(await post(s, codeForm(only))), INVALID_GRANT);
    assert.ok(s.events.some((e) => e.type === "token.refused" && e.reason === "no_scope"));
    assert.equal((await s.fd.listGrants("user-1")).length, 1, "no grant for the refused code");
  });

  it("a mint that fails during a refresh leaves the presented refresh token usable", async () => {
    let failing: "throw" | "registered" | null = null;
    const h = await harness({
      accessTokenClaims: () => {
        if (failing === "throw") throw new Error("claims backend down");
        return failing === "registered" ? { sub: "someone-else" } : {};
      },
    });
    const first = await connect(h);
    const refresh = async (mode: typeof failing) => {
      failing = mode;
      return slim(await post(h, refreshForm(first.refresh_token)));
    };

    assert.deepEqual(await refresh("throw"), { status: 500, body: { error: "server_error" } });
    assert.deepEqual(await refresh("registered"), { status: 500, body: { error: "server_error" } });

    // Nothing was spent: the same token refreshes, and the family is intact.
    const after = await refresh(null);
    assert.equal(after.status, 200);
    assert.equal((await h.fd.listGrants("user-1")).length, 1);
    assert.ok(!h.events.some((e) => e.type === "grant.revoked"));
    assert.equal(h.events.filter((e) => e.type === "grant.refreshed").length, 1);
  });

  it("a mint that fails during a code exchange stores no grant", async () => {
    const h = await harness({
      accessTokenClaims: () => {
        throw new Error("claims backend down");
      },
    });
    const code = await approveCode(h);
    assert.deepEqual(slim(await post(h, codeForm(code))), { status: 500, body: { error: "server_error" } });
    assert.deepEqual(await h.fd.listGrants("user-1"), []);
    assert.ok(!h.events.some((e) => e.type === "grant.created"));
  });
});
