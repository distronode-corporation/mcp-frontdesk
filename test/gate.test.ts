// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { bearerTokenFrom } from "../src/gate.ts";
import { connect, harness, ISSUER, resourceRequest } from "./helpers.ts";

const PRM = `${ISSUER}/.well-known/oauth-protected-resource/mcp`;

describe("bearerTokenFrom", () => {
  it("reads one bearer token, any case of the scheme, surrounding space trimmed", () => {
    assert.equal(bearerTokenFrom("Bearer abc.def"), "abc.def");
    assert.equal(bearerTokenFrom("  bearer\tabc  "), "abc");
    for (const bad of [null, undefined, "", "Bearer", "Bearer ", "Basic abc", "Bearer a b", "Bearerabc"]) {
      assert.equal(bearerTokenFrom(bad), null, String(bad));
    }
  });
});

describe("authenticate", () => {
  it("lets a valid token through on the resource path, with its claims", async () => {
    const h = await harness();
    const { access_token } = await connect(h);
    const result = await h.fd.authenticate(resourceRequest(access_token));
    assert.ok(result.ok);
    assert.equal(result.token.subject, "user-1");
    assert.deepEqual(result.token.scopes, ["notes:read"]);
  });

  it("no header: 401 naming the resource metadata, so the client can discover the server", async () => {
    const h = await harness();
    const result = await h.fd.authenticate(resourceRequest(null));
    assert.ok(!result.ok);
    assert.equal(result.response.status, 401);
    assert.equal(result.response.headers.get("www-authenticate"), `Bearer resource_metadata="${PRM}"`);
    assert.equal(result.response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await result.response.json(), { error: "unauthorized" });
  });

  it("every presented-but-refused token gets the same invalid_token 401", async () => {
    const h = await harness();
    const { access_token } = await connect(h);
    const refused = [
      resourceRequest(null, "/mcp", { Authorization: "Basic YTpi" }),
      resourceRequest("not-a-jwt"),
      resourceRequest(`${access_token}x`),
      resourceRequest(access_token, "/admin"),
      resourceRequest(access_token, "/mcp/"),
    ];
    for (const req of refused) {
      const result = await h.fd.authenticate(req);
      assert.ok(!result.ok);
      assert.equal(result.response.status, 401);
      assert.equal(result.response.headers.get("www-authenticate"), `Bearer resource_metadata="${PRM}", error="invalid_token"`);
      assert.deepEqual(await result.response.json(), { error: "invalid_token" });
    }
  });

  it("an expired token is refused the same way", async () => {
    const h = await harness();
    const { access_token } = await connect(h);
    h.clock.advance(700_000);
    const result = await h.fd.authenticate(resourceRequest(access_token));
    assert.ok(!result.ok);
    assert.equal(result.response.status, 401);
    assert.equal(result.response.headers.get("www-authenticate"), `Bearer resource_metadata="${PRM}", error="invalid_token"`);
    assert.deepEqual(await result.response.json(), { error: "invalid_token" });
  });

  it("an Authorization header that is present but empty is a refused credential, not a missing one", async () => {
    const h = await harness();
    const result = await h.fd.authenticate(resourceRequest(null, "/mcp", { Authorization: "" }));
    assert.ok(!result.ok);
    assert.equal(result.response.status, 401);
    assert.equal(result.response.headers.get("www-authenticate"), `Bearer resource_metadata="${PRM}", error="invalid_token"`);
    assert.deepEqual(await result.response.json(), { error: "invalid_token" });
  });

  it("accepts every configured resource path, and only those", async () => {
    const h = await harness({ resourcePaths: ["/mcp", "/mcp/sse"] });
    const { access_token } = await connect(h);
    assert.ok((await h.fd.authenticate(resourceRequest(access_token, "/mcp/sse"))).ok);
    assert.ok(!(await h.fd.authenticate(resourceRequest(access_token, "/mcp/other"))).ok);
  });

  it("a token without a required scope gets a 403 step-up challenge naming every scope needed", async () => {
    const h = await harness();
    const { access_token } = await connect(h);
    const result = await h.fd.authenticate(resourceRequest(access_token), { requiredScopes: ["notes:read", "notes:write"] });
    assert.ok(!result.ok);
    assert.equal(result.response.status, 403);
    assert.equal(
      result.response.headers.get("www-authenticate"),
      `Bearer resource_metadata="${PRM}", error="insufficient_scope", scope="notes:read notes:write"`,
    );
    assert.ok((await h.fd.authenticate(resourceRequest(access_token), { requiredScopes: ["notes:read"] })).ok);
    await assert.rejects(h.fd.authenticate(resourceRequest(access_token), { requiredScopes: ["notes:admin"] }), TypeError);
  });

  it("refuses a browser Origin that is not allowed before anything else, and admits an allowed one", async () => {
    const h = await harness();
    const { access_token } = await connect(h);
    const evil = await h.fd.authenticate(resourceRequest(access_token, "/mcp", { Origin: "https://evil.example.net" }));
    assert.ok(!evil.ok);
    assert.equal(evil.response.status, 403);
    assert.deepEqual(await evil.response.json(), { error: "forbidden_origin" });
    assert.ok((await h.fd.authenticate(resourceRequest(access_token, "/mcp", { Origin: "https://app.example.com" }))).ok);
  });

  it("consults the rate limiter for the resource", async () => {
    const h = await harness({ rateLimiter: { allow: (endpoint) => endpoint !== "resource" } });
    const result = await h.fd.authenticate(resourceRequest("x"));
    assert.ok(!result.ok);
    assert.equal(result.response.status, 429);
    assert.equal(result.response.headers.get("retry-after"), "60");
  });

  it("a rate limiter that fails is reported and refuses with 503, never an exception into the host", async () => {
    const h = await harness({
      rateLimiter: {
        allow: (endpoint) => (endpoint === "resource" ? Promise.reject(new Error("limiter backend down")) : true),
      },
    });
    const { access_token } = await connect(h);
    const result = await h.fd.authenticate(resourceRequest(access_token));
    assert.ok(!result.ok);
    assert.equal(result.response.status, 503);
    assert.equal(result.response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await result.response.json(), { error: "temporarily_unavailable" });
    assert.equal(h.reports.at(-1)?.where, "rateLimiter.resource");
  });

  it("exposes the challenges for a host that refuses on its own", async () => {
    const h = await harness();
    assert.equal(h.fd.unauthorized(true).status, 401);
    assert.equal(h.fd.insufficientScope(["notes:write"]).status, 403);
    assert.equal(h.fd.protectedResourceMetadataUrl, PRM);
  });
});
