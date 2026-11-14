import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { claudeClients, DEFAULT_TTL, FrontdeskConfigError, resolveConfig, type FrontdeskConfig } from "../src/config.ts";
import { createFrontdesk } from "../src/frontdesk.ts";
import { authorizationServerMetadataUrl, protectedResourceMetadataUrl } from "../src/discovery.ts";
import { MemoryCodeStore, MemoryGrantStore } from "../src/memory-stores.ts";
import { harness, ISSUER, RESOURCE } from "./helpers.ts";

const keys = { signingKey: async () => null, verificationKey: async () => null };
const base: FrontdeskConfig = {
  issuer: ISSUER,
  resource: RESOURCE,
  scopes: ["notes:read"],
  authorizationEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientIdHosts: ["client.example.com"],
  redirectUris: ["https://client.example.com/callback"],
  allowedOrigins: [],
  keys,
  codeStore: new MemoryCodeStore(),
  grantStore: new MemoryGrantStore(),
};

describe("resolveConfig", () => {
  it("fills in the defaults, and none of them is a product value", () => {
    const config = resolveConfig(base);
    assert.deepEqual(config.resourcePaths, ["/mcp"]);
    assert.deepEqual(config.defaultScopes, ["notes:read"]);
    assert.deepEqual(config.requestableScopes, ["notes:read", "offline_access"]);
    assert.equal(config.authorizationEndpoint, "https://mcp.example.com/authorize");
    assert.equal(config.tokenEndpoint, "https://mcp.example.com/token");
    assert.equal(config.allowLoopbackRedirects, false);
    assert.equal(config.codeTtlSeconds, DEFAULT_TTL.authorizationCode);
    assert.equal(config.accessTtlSeconds, 600);
    assert.equal(config.refreshTtlSeconds, 30 * 86_400);
    assert.equal(config.refreshTokenReuse, "revoke-family");
    assert.equal(config.now, Date.now);
    assert.equal(config.resourceName, undefined);
  });

  it("takes absolute endpoints, explicit paths, lifetimes and the preset", () => {
    const config = resolveConfig({
      ...base,
      ...claudeClients,
      issuer: "http://localhost:3000",
      resource: "http://localhost:3000",
      resourcePaths: ["/mcp", "/mcp/stream"],
      tokenEndpoint: "https://auth.example.com/oauth/token",
      ttl: { authorizationCode: 30, accessToken: 300, refreshToken: 3600 },
      refreshTokenReuse: "refuse",
    });
    assert.equal(config.tokenEndpoint, "https://auth.example.com/oauth/token");
    assert.equal(config.authorizationEndpoint, "http://localhost:3000/authorize");
    assert.deepEqual(config.clientIdHosts, ["claude.ai", "claude.com"]);
    assert.equal(config.allowLoopbackRedirects, true);
    assert.deepEqual([config.codeTtlSeconds, config.accessTtlSeconds, config.refreshTtlSeconds], [30, 300, 3600]);
    assert.equal(config.refreshTokenReuse, "refuse");
  });

  const bad: [string, Partial<Record<keyof FrontdeskConfig, unknown>>, RegExp][] = [
    ["a non-string issuer", { issuer: 1 }, /issuer must be a string/],
    ["an issuer that is not a URL", { issuer: "mcp.example.com" }, /issuer is not a URL/],
    ["a plain-http issuer off loopback", { issuer: "http://mcp.example.com" }, /issuer must be https/],
    ["an issuer with a trailing slash", { issuer: "https://mcp.example.com/" }, /issuer must be canonical/],
    ["an upper-case resource", { resource: "https://MCP.example.com/mcp" }, /resource must be canonical/],
    ["a resource with a fragment", { resource: "https://mcp.example.com/mcp#x" }, /resource must be canonical/],
    ["a resource with a query", { resource: "https://mcp.example.com/mcp?x" }, /resource must be canonical/],
    ["a resource with userinfo", { resource: "https://u@mcp.example.com/mcp" }, /resource must be canonical/],
    ["no scopes", { scopes: [] }, /scopes must not be empty/],
    ["scopes that are not strings", { scopes: ["a", 2] }, /scopes must be an array/],
    ["a scope with a space", { scopes: ["a b"] }, /not a valid scope token/],
    ["offline_access as a resource scope", { scopes: ["offline_access"] }, /not a resource scope/],
    ["default scopes outside scopes", { defaultScopes: ["notes:write"] }, /subset of scopes/],
    ["empty default scopes", { defaultScopes: [] }, /defaultScopes must not be empty/],
    ["a relative resource path", { resourcePaths: ["mcp"] }, /absolute paths/],
    ["no client hosts", { clientIdHosts: [] }, /clientIdHosts must not be empty/],
    ["an http redirect URI", { redirectUris: ["http://client.example.com/cb"] }, /canonical https URL/],
    ["a redirect URI with a fragment", { redirectUris: ["https://client.example.com/cb#x"] }, /canonical https URL/],
    ["no redirect URIs and no loopback", { redirectUris: [] }, /no redirect URI could ever be accepted/],
    ["an allowed origin with a path", { allowedOrigins: ["https://app.example.com/"] }, /must be an origin/],
    ["a missing allowed origins list", { allowedOrigins: undefined }, /allowedOrigins must be an array/],
    ["an empty endpoint", { tokenEndpoint: "" }, /tokenEndpoint must be a path or a URL/],
    ["an http endpoint", { authorizationEndpoint: "http://auth.example.com/a" }, /authorizationEndpoint must be https/],
    ["a zero lifetime", { ttl: { accessToken: 0 } }, /ttl.accessToken must be a positive integer/],
    ["a fractional lifetime", { ttl: { refreshToken: 1.5 } }, /ttl.refreshToken/],
    ["an unknown reuse policy", { refreshTokenReuse: "ignore" }, /refreshTokenReuse must be/],
    ["no key provider", { keys: undefined }, /keys is required/],
    ["no code store", { codeStore: null }, /codeStore is required/],
    ["no grant store", { grantStore: undefined }, /grantStore is required/],
  ];
  for (const [what, change, message] of bad) {
    it(`refuses ${what}`, () => {
      assert.throws(
        () => resolveConfig({ ...base, ...change } as FrontdeskConfig),
        (err: unknown) => err instanceof FrontdeskConfigError && message.test(err.message) && err.message.startsWith("mcp-frontdesk config: "),
      );
    });
  }

  it("refuses no config at all", () => {
    assert.throws(() => resolveConfig(null as never), /a config object is required/);
    assert.throws(() => createFrontdesk(undefined as never), FrontdeskConfigError);
  });

  it("accepts loopback redirects with no hosted URIs", () => {
    assert.equal(resolveConfig({ ...base, redirectUris: [], allowLoopbackRedirects: true }).redirectUris.length, 0);
  });
});

describe("discovery documents", () => {
  it("serves RFC 9728 and RFC 8414 documents built only from the config", async () => {
    const h = await harness({ resourceName: "Example Notes" });
    assert.deepEqual(h.fd.protectedResourceMetadata(), {
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      scopes_supported: ["notes:read", "notes:write"],
      bearer_methods_supported: ["header"],
      resource_name: "Example Notes",
    });
    assert.deepEqual(h.fd.authorizationServerMetadata(), {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      client_id_metadata_document_supported: true,
      scopes_supported: ["notes:read", "notes:write", "offline_access"],
      authorization_response_iss_parameter_supported: true,
    });
    assert.equal("registration_endpoint" in h.fd.authorizationServerMetadata(), false);
    assert.equal("jwks_uri" in h.fd.authorizationServerMetadata(), false);
    assert.equal("resource_name" in (await harness()).fd.protectedResourceMetadata(), false);
  });

  it("builds the well-known URLs, path-inserted", () => {
    assert.equal(protectedResourceMetadataUrl("https://mcp.example.com/mcp"), "https://mcp.example.com/.well-known/oauth-protected-resource/mcp");
    assert.equal(protectedResourceMetadataUrl("https://mcp.example.com"), "https://mcp.example.com/.well-known/oauth-protected-resource");
    assert.equal(authorizationServerMetadataUrl("https://mcp.example.com"), "https://mcp.example.com/.well-known/oauth-authorization-server");
    assert.equal(authorizationServerMetadataUrl("https://auth.example.com/tenant-a"), "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a");
  });

  it("answers both PRM forms and the AS document as public, cacheable JSON, and nothing else", async () => {
    const h = await harness();
    for (const [path, key] of [
      ["/.well-known/oauth-protected-resource/mcp", "resource"],
      ["/.well-known/oauth-protected-resource", "resource"],
      ["/.well-known/oauth-authorization-server", "issuer"],
    ] as const) {
      const res = h.fd.handleDiscovery(new Request(`${ISSUER}${path}`))!;
      assert.equal(res.status, 200, path);
      assert.equal(res.headers.get("content-type"), "application/json");
      assert.equal(res.headers.get("cache-control"), "public, max-age=3600");
      assert.equal(res.headers.get("access-control-allow-origin"), "*");
      assert.ok(key in ((await res.json()) as object));
    }
    assert.equal(h.fd.handleDiscovery(new Request(`${ISSUER}/.well-known/other`)), null);
    assert.equal(h.fd.handleDiscovery(new Request(`${ISSUER}/mcp`)), null);
  });

  it("answers HEAD with no body, OPTIONS with CORS, and refuses other methods", async () => {
    const h = await harness();
    const url = `${ISSUER}/.well-known/oauth-authorization-server`;
    const head = h.fd.handleDiscovery(new Request(url, { method: "HEAD" }))!;
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
    const options = h.fd.handleDiscovery(new Request(url, { method: "OPTIONS" }))!;
    assert.equal(options.status, 204);
    assert.equal(options.headers.get("access-control-allow-methods"), "GET");
    const post = h.fd.handleDiscovery(new Request(url, { method: "POST" }))!;
    assert.equal(post.status, 405);
    assert.equal(post.headers.get("allow"), "GET, HEAD, OPTIONS");
  });

  it("serves a resource at the origin root and an issuer with a path", async () => {
    const h = await harness({ resource: ISSUER, issuer: "https://mcp.example.com/tenant-a" });
    assert.ok(h.fd.handleDiscovery(new Request(`${ISSUER}/.well-known/oauth-protected-resource`)));
    assert.ok(h.fd.handleDiscovery(new Request(`${ISSUER}/.well-known/oauth-authorization-server/tenant-a`)));
    assert.equal(h.fd.handleDiscovery(new Request(`${ISSUER}/.well-known/oauth-authorization-server`)), null);
    assert.deepEqual(h.fd.config.resourcePaths, ["/"]);
    assert.equal(h.fd.protectedResourceMetadataUrl, `${ISSUER}/.well-known/oauth-protected-resource`);
  });
});

describe("the default client metadata fetch", () => {
  it("goes through the SSRF guard with the system resolver, refusing an internal host before any lookup", async () => {
    const fd = createFrontdesk({ ...base, clientIdHosts: ["client.localhost"] });
    const check = await fd.checkAuthorizeRequest({ client_id: "https://client.localhost/m.json" });
    assert.deepEqual(check, { ok: false, kind: "page", error: "invalid_client" });
  });
});
