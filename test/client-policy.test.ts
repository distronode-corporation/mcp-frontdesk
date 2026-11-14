import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { isAllowedRedirectUri, isLoopbackRedirect, matchesRegisteredRedirect, trustedClientIdHost } from "../src/client-policy.ts";
import { claudeClients } from "../src/config.ts";

const HOSTS = ["client.example.com", "apps.example.org"];

describe("trustedClientIdHost", () => {
  it("answers the host of an https client_id on the allowlist", () => {
    assert.equal(trustedClientIdHost("https://client.example.com/m.json", HOSTS), "client.example.com");
    assert.equal(trustedClientIdHost("https://apps.example.org/a/b", HOSTS), "apps.example.org");
  });

  it("refuses other hosts, subdomains, http and non-URLs", () => {
    for (const id of [
      "https://evil.example.net/m.json",
      "https://sub.client.example.com/m.json",
      "https://client.example.com.evil.example.net/m.json",
      "http://client.example.com/m.json",
      "client.example.com/m.json",
      "",
    ]) {
      assert.equal(trustedClientIdHost(id, HOSTS), null, id);
    }
  });

  it("the Claude preset names its two hosts and two callbacks, and allows loopback", () => {
    assert.deepEqual([...claudeClients.clientIdHosts], ["claude.ai", "claude.com"]);
    assert.deepEqual([...claudeClients.redirectUris], ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"]);
    assert.equal(claudeClients.allowLoopbackRedirects, true);
    assert.ok(Object.isFrozen(claudeClients) && Object.isFrozen(claudeClients.clientIdHosts));
  });
});

describe("isLoopbackRedirect", () => {
  it("knows the three loopback hosts over http only", () => {
    for (const uri of ["http://localhost:3118/callback", "http://127.0.0.1/callback", "http://[::1]:9/x"]) assert.equal(isLoopbackRedirect(uri), true, uri);
    for (const uri of ["https://localhost/callback", "http://10.0.0.1/cb", "http://127.0.0.2/cb", "::"]) assert.equal(isLoopbackRedirect(uri), false, uri);
  });
});

describe("isAllowedRedirectUri", () => {
  const hosted = ["https://client.example.com/callback"];

  it("accepts a configured URI exactly, and canonical loopback when allowed", () => {
    assert.equal(isAllowedRedirectUri("https://client.example.com/callback", hosted, false), true);
    assert.equal(isAllowedRedirectUri("http://localhost/callback", hosted, true), true);
    assert.equal(isAllowedRedirectUri("http://127.0.0.1:8080/cb?x=1", hosted, true), true);
  });

  it("refuses loopback when not allowed, and every non-canonical or decorated form", () => {
    assert.equal(isAllowedRedirectUri("http://localhost/callback", hosted, false), false);
    for (const uri of [
      "https://client.example.com/callback/",
      "https://client.example.com/other",
      "http://LOCALHOST/callback",
      "http://user@localhost/callback",
      "http://user:pw@127.0.0.1/callback",
      "http://localhost/callback#frag",
      "http://localhost/callback#",
      "http://localhost/a/../callback",
      "https://localhost/callback",
      "not a url",
    ]) {
      assert.equal(isAllowedRedirectUri(uri, hosted, true), false, uri);
    }
  });
});

describe("matchesRegisteredRedirect", () => {
  it("matches a hosted callback exactly", () => {
    assert.equal(matchesRegisteredRedirect("https://client.example.com/callback", ["https://client.example.com/callback"]), true);
    assert.equal(matchesRegisteredRedirect("https://client.example.com/callback/", ["https://client.example.com/callback"]), false);
  });

  it("matches a loopback registration with any port, and with none", () => {
    const registered = ["http://localhost/callback", "http://127.0.0.1/callback"];
    for (const uri of ["http://localhost:51234/callback", "http://127.0.0.1:9/callback", "http://localhost/callback"]) {
      assert.equal(matchesRegisteredRedirect(uri, registered), true, uri);
    }
  });

  it("refuses a different path, query, host, userinfo, fragment or a non-canonical request", () => {
    const registered = ["http://localhost/callback?x=1"];
    for (const uri of [
      "http://localhost:5/other?x=1",
      "http://localhost:5/callback?x=2",
      "http://localhost:5/callback",
      "http://127.0.0.1:5/callback?x=1",
      "http://u@localhost:5/callback?x=1",
      "http://localhost:5/callback?x=1#",
      "http://localhost:5/a/../callback?x=1",
      "https://localhost:5/callback?x=1",
      "garbage",
    ]) {
      assert.equal(matchesRegisteredRedirect(uri, registered), false, uri);
    }
  });

  it("never crosses loopback hosts, and skips registrations that are not loopback or not URLs", () => {
    assert.equal(matchesRegisteredRedirect("http://localhost:5/cb", ["http://127.0.0.1/cb", "https://localhost/cb", "::bad"]), false);
    assert.equal(matchesRegisteredRedirect("http://[::1]:5/cb", ["::bad", "http://[::1]/cb"]), true);
    assert.equal(matchesRegisteredRedirect("http://localhost:5/cb", ["http://u:p@localhost/cb"]), false);
  });
});
