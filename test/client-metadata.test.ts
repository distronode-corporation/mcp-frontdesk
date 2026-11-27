// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

import { strict as assert } from "node:assert";
import { createServer, request as httpRequest, type RequestOptions } from "node:http";
import type { AddressInfo, LookupFunction } from "node:net";
import { after, before, describe, it } from "node:test";

import { cacheTtlMs, ClientMetadataFetcher, isValidClientIdUrl, type ClientMetadataOptions } from "../src/client-metadata.ts";
import { isAllowedRedirectUri } from "../src/client-policy.ts";
import type { Transport } from "../src/pinned-get.ts";
import { CLIENT_DOCUMENT, CLIENT_ID, clock, HOSTED_REDIRECT, jsonResponse } from "./helpers.ts";

function fetcher(fetchImpl: ClientMetadataOptions["unsafeFetch"], time = clock(), extra: Partial<ClientMetadataOptions> = {}) {
  return new ClientMetadataFetcher({
    isAllowedRedirectUri: (uri) => isAllowedRedirectUri(uri, [HOSTED_REDIRECT], true),
    resolveHost: async () => {
      throw new Error("the resolver must not be asked when an unsafe fetch is set");
    },
    unsafeFetch: fetchImpl,
    now: time.now,
    ...extra,
  });
}

const serve = (body: unknown, init: ResponseInit = {}) => {
  const calls: string[] = [];
  const impl = async (url: string) => {
    calls.push(url);
    return typeof body === "function" ? (body as () => Response)() : jsonResponse(body, init);
  };
  return { impl, calls };
};

describe("isValidClientIdUrl", () => {
  it("accepts canonical https URLs with a path and a name host", () => {
    for (const url of [CLIENT_ID, "https://example.com/client.json", "https://sub.example.co.uk/a/b/c"]) assert.equal(isValidClientIdUrl(url), true, url);
  });

  it("refuses everything that would be fetched as a different string", () => {
    for (const url of [
      "http://example.com/c.json",
      "https://example.com",
      "https://example.com/",
      "https://example.com:443/c.json",
      "https://example.com:8443/c.json",
      "https://EXAMPLE.com/c.json",
      "https://example.com/a/../c.json",
      "https://user@example.com/c.json",
      "https://u:p@example.com/c.json",
      "https://example.com/c.json?x=1",
      "https://example.com/c.json?",
      "https://example.com/c.json#f",
      "https://example.com/c.json#",
      "https://93.184.215.14/c.json",
      "https://[2606:2800::1]/c.json",
      " https://example.com/c.json",
      `https://example.com/${"a".repeat(500)}`,
      "not a url",
    ]) {
      assert.equal(isValidClientIdUrl(url), false, url);
    }
  });
});

describe("cacheTtlMs", () => {
  it("defaults to five minutes, honours a shorter max-age, caps at an hour, and refuses to cache private answers", () => {
    assert.equal(cacheTtlMs(null), 300_000);
    assert.equal(cacheTtlMs("public"), 300_000);
    assert.equal(cacheTtlMs("max-age=30"), 30_000);
    assert.equal(cacheTtlMs("Max-Age=999999"), 3_600_000);
    for (const value of ["no-store", "no-cache", "private, max-age=600", "max-age=0"]) assert.equal(cacheTtlMs(value), 0, value);
  });
});

describe("ClientMetadataFetcher with the unsafe fetch option", () => {
  it("returns the validated document, trimming the name", async () => {
    const { impl, calls } = serve({ ...CLIENT_DOCUMENT, client_name: "  Example Client  " });
    const result = await fetcher(impl).fetch(CLIENT_ID);
    assert.deepEqual(result, {
      ok: true,
      metadata: { clientId: CLIENT_ID, clientName: "Example Client", redirectUris: CLIENT_DOCUMENT.redirect_uris },
    });
    assert.deepEqual(calls, [CLIENT_ID]);
  });

  it("accepts a document with no token_endpoint_auth_method, and +json types", async () => {
    const { token_endpoint_auth_method: _omit, ...doc } = CLIENT_DOCUMENT;
    const { impl } = serve(doc, { headers: { "Content-Type": "application/oauth-client-metadata+json" } });
    assert.equal((await fetcher(impl).fetch(CLIENT_ID)).ok, true);
  });

  it("refuses an invalid client_id without fetching", async () => {
    const { impl, calls } = serve(CLIENT_DOCUMENT);
    assert.deepEqual(await fetcher(impl).fetch("http://client.example.com/x"), { ok: false, reason: "invalid_client_id" });
    assert.equal(calls.length, 0);
  });

  const refusals: [string, unknown, ClientMetadataRefusalName][] = [
    ["not an object", [1, 2], "invalid_document"],
    ["another client_id", { ...CLIENT_DOCUMENT, client_id: "https://client.example.com/other.json" }, "client_id_mismatch"],
    ["a client secret", { ...CLIENT_DOCUMENT, client_secret: "s" }, "confidential_client"],
    ["a secret expiry", { ...CLIENT_DOCUMENT, client_secret_expires_at: 0 }, "confidential_client"],
    ["a shared-secret auth method", { ...CLIENT_DOCUMENT, token_endpoint_auth_method: "client_secret_basic" }, "confidential_client"],
    ["no name", { ...CLIENT_DOCUMENT, client_name: undefined }, "invalid_document"],
    ["a blank name", { ...CLIENT_DOCUMENT, client_name: "   " }, "invalid_document"],
    ["a long name", { ...CLIENT_DOCUMENT, client_name: "x".repeat(81) }, "invalid_document"],
    ["a control character in the name", { ...CLIENT_DOCUMENT, client_name: "Bad\u0007Name" }, "invalid_document"],
    ["no redirect URIs", { ...CLIENT_DOCUMENT, redirect_uris: [] }, "invalid_redirect_uris"],
    ["redirect URIs that are not a list", { ...CLIENT_DOCUMENT, redirect_uris: HOSTED_REDIRECT }, "invalid_redirect_uris"],
    ["eleven redirect URIs", { ...CLIENT_DOCUMENT, redirect_uris: Array(11).fill(HOSTED_REDIRECT) }, "invalid_redirect_uris"],
    ["one URI outside the allowlist", { ...CLIENT_DOCUMENT, redirect_uris: [HOSTED_REDIRECT, "https://evil.example.net/cb"] }, "invalid_redirect_uris"],
    ["a non-string URI", { ...CLIENT_DOCUMENT, redirect_uris: [HOSTED_REDIRECT, 7] }, "invalid_redirect_uris"],
  ];
  type ClientMetadataRefusalName = string;
  for (const [what, doc, reason] of refusals) {
    it(`refuses a document with ${what}`, async () => {
      assert.deepEqual(await fetcher(serve(doc).impl).fetch(CLIENT_ID), { ok: false, reason });
    });
  }

  it("refuses a non-200, a non-JSON type and unparseable JSON", async () => {
    assert.deepEqual(await fetcher(serve(CLIENT_DOCUMENT, { status: 404 }).impl).fetch(CLIENT_ID), { ok: false, reason: "http_status" });
    const html = serve(() => new Response("<html>", { headers: { "Content-Type": "text/html" } }));
    assert.deepEqual(await fetcher(html.impl).fetch(CLIENT_ID), { ok: false, reason: "not_json" });
    const broken = serve(() => new Response("{nope", { headers: { "Content-Type": "application/json" } }));
    assert.deepEqual(await fetcher(broken.impl).fetch(CLIENT_ID), { ok: false, reason: "not_json" });
    const empty = serve(() => new Response(null, { headers: { "Content-Type": "application/json" } }));
    assert.deepEqual(await fetcher(empty.impl).fetch(CLIENT_ID), { ok: false, reason: "not_json" });
  });

  it("still answers when a refused body cannot be cancelled", async () => {
    const res = jsonResponse(CLIENT_DOCUMENT, { status: 500 });
    Object.defineProperty(res, "body", { value: { cancel: () => Promise.reject(new Error("no")) } });
    assert.deepEqual(await fetcher(async () => res).fetch(CLIENT_ID), { ok: false, reason: "http_status" });
  });

  it("treats a fetch that throws, or a body that breaks, as unreachable", async () => {
    const throws = fetcher(async () => {
      throw new TypeError("fetch failed");
    });
    assert.deepEqual(await throws.fetch(CLIENT_ID), { ok: false, reason: "unreachable" });
    const breaking = new ReadableStream({
      start(controller) {
        controller.error(new Error("reset"));
      },
    });
    const breaks = fetcher(async () => new Response(breaking, { headers: { "Content-Type": "application/json" } }));
    assert.deepEqual(await breaks.fetch(CLIENT_ID), { ok: false, reason: "unreachable" });
  });

  it("gives the fetch 5 seconds, then aborts its signal and refuses it, even a fetch that ignores the signal", { timeout: 5_000 }, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let signal: AbortSignal | undefined;
    const pending = fetcher((_url, init) => {
      signal = init.signal;
      return new Promise<Response>(() => undefined); // never answers, never listens
    }).fetch(CLIENT_ID);
    t.mock.timers.tick(4_999);
    assert.ok(signal instanceof AbortSignal && !signal.aborted);
    t.mock.timers.tick(1);
    assert.deepEqual(await pending, { ok: false, reason: "unreachable" });
    assert.equal(signal.aborted, true);
    // A timeout, not a cancel: a host's fetch can tell the two apart.
    assert.ok(signal.reason instanceof DOMException && signal.reason.name === "TimeoutError", String(signal.reason));
  });

  it("holds the body read to the same deadline, and cancels the read when it passes", { timeout: 5_000 }, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let cancelled: unknown = "not cancelled";
    const stalled = new ReadableStream<Uint8Array>({
      pull: () => new Promise(() => undefined),
      cancel(reason) {
        cancelled = reason;
      },
    });
    let started!: () => void;
    const reading = new Promise<void>((resolve) => (started = resolve));
    const pending = fetcher(async () => {
      queueMicrotask(started);
      return new Response(stalled, { headers: { "Content-Type": "application/json" } });
    }).fetch(CLIENT_ID);
    await reading;
    t.mock.timers.tick(5_000);
    assert.deepEqual(await pending, { ok: false, reason: "unreachable" });
    // The stalled body is let go of, not left waiting on a read that will never finish.
    assert.ok(cancelled instanceof DOMException && cancelled.name === "TimeoutError", String(cancelled));
  });

  it("a deadline that passed before the body is read cancels it unread", { timeout: 5_000 }, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let pulled = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>(
      {
        pull: () => void (pulled += 1),
        cancel: () => void (cancelled = true),
      },
      { highWaterMark: 0 },
    );
    let answer!: (res: Response) => void;
    const pending = fetcher(() => new Promise<Response>((resolve) => (answer = resolve))).fetch(CLIENT_ID);
    await Promise.resolve();
    t.mock.timers.tick(5_000);
    // The fetch answers only after the deadline; its body is never read.
    answer(new Response(body, { headers: { "Content-Type": "application/json" } }));
    assert.deepEqual(await pending, { ok: false, reason: "unreachable" });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(pulled, 0);
    assert.equal(cancelled, true);
  });

  it("caps the body at 5 KB while streaming, and accepts exactly 5 KB", async () => {
    const padded = (size: number) => {
      const base = JSON.stringify({ ...CLIENT_DOCUMENT, pad: "" });
      return JSON.stringify({ ...CLIENT_DOCUMENT, pad: "x".repeat(size - base.length) });
    };
    const exact = serve(() => new Response(padded(5 * 1024), { headers: { "Content-Type": "application/json" } }));
    assert.equal((await fetcher(exact.impl).fetch(CLIENT_ID)).ok, true);
    const over = serve(() => new Response(padded(5 * 1024 + 1), { headers: { "Content-Type": "application/json" } }));
    assert.deepEqual(await fetcher(over.impl).fetch(CLIENT_ID), { ok: false, reason: "too_large" });
  });
});

describe("ClientMetadataFetcher caching", () => {
  it("serves a good document from cache for five minutes by default, then fetches again", async () => {
    const time = clock();
    const { impl, calls } = serve(CLIENT_DOCUMENT);
    const f = fetcher(impl, time);
    await f.fetch(CLIENT_ID);
    time.advance(299_999);
    await f.fetch(CLIENT_ID);
    assert.equal(calls.length, 1);
    time.advance(1);
    await f.fetch(CLIENT_ID);
    assert.equal(calls.length, 2);
  });

  it("never caches a refusal, nor a document marked no-store", async () => {
    const bad = serve({ ...CLIENT_DOCUMENT, client_id: "https://client.example.com/x" });
    const f = fetcher(bad.impl);
    await f.fetch(CLIENT_ID);
    await f.fetch(CLIENT_ID);
    assert.equal(bad.calls.length, 2);
    const noStore = serve(CLIENT_DOCUMENT, { headers: { "Cache-Control": "no-store" } });
    const g = fetcher(noStore.impl);
    await g.fetch(CLIENT_ID);
    await g.fetch(CLIENT_ID);
    assert.equal(noStore.calls.length, 2);
  });

  it("holds at most 100 documents, evicting the oldest", async () => {
    const calls: string[] = [];
    const f = fetcher(async (url) => {
      calls.push(url);
      return jsonResponse({ ...CLIENT_DOCUMENT, client_id: url });
    });
    const ids = Array.from({ length: 101 }, (_, i) => `https://client.example.com/c/${i}.json`);
    for (const id of ids) await f.fetch(id);
    await f.fetch(ids[100]!);
    await f.fetch(ids[1]!);
    assert.equal(calls.length, 101);
    await f.fetch(ids[0]!);
    assert.equal(calls.length, 102);
  });
});

describe("ClientMetadataFetcher through the SSRF guard (safety property 1)", () => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(CLIENT_DOCUMENT));
  });
  let port = 0;
  before(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });
  after(() => {
    server.closeAllConnections();
    server.close();
  });

  /** Records what the pinned lookup answers, then connects to the local server instead. */
  function recordingTransport(): { transport: Transport; pinned: unknown[] } {
    const pinned: unknown[] = [];
    const loopback: LookupFunction = (_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }]);
    const transport: Transport = {
      port: 0,
      request: (options: RequestOptions, callback) => {
        options.lookup!("client.example.com", { all: true }, (_err, addresses) => pinned.push(addresses));
        return httpRequest({ ...options, port, lookup: loopback }, callback);
      },
    };
    return { transport, pinned };
  }

  const guarded = (resolveHost: ClientMetadataOptions["resolveHost"], transport?: Transport) =>
    fetcher(undefined, clock(), { resolveHost, ...(transport ? { transport } : {}) });

  it("resolves once, pins the checked public addresses, and validates what comes back", async () => {
    const { transport, pinned } = recordingTransport();
    const lookups: string[] = [];
    const f = guarded(async (host) => {
      lookups.push(host);
      return [{ address: "93.184.215.14", family: 4 }];
    }, transport);
    const result = await f.fetch(CLIENT_ID);
    assert.equal(result.ok, true);
    assert.deepEqual(lookups, ["client.example.com"]);
    assert.deepEqual(pinned, [[{ address: "93.184.215.14", family: 4 }]]);
  });

  it("refuses a host that resolves to a private address, without connecting", async () => {
    const { transport, pinned } = recordingTransport();
    const f = guarded(async () => [{ address: "169.254.169.254", family: 4 }], transport);
    assert.deepEqual(await f.fetch(CLIENT_ID), { ok: false, reason: "blocked" });
    assert.equal(pinned.length, 0);
  });

  it("refuses an internal name before resolving it", async () => {
    let asked = false;
    const f = guarded(async () => {
      asked = true;
      return [{ address: "93.184.215.14", family: 4 }];
    });
    assert.deepEqual(await f.fetch("https://printer.local/c.json"), { ok: false, reason: "blocked" });
    assert.equal(asked, false);
  });

  it("answers unreachable for a name that does not resolve", async () => {
    const f = guarded(async () => {
      throw new Error("ENOTFOUND");
    });
    assert.deepEqual(await f.fetch(CLIENT_ID), { ok: false, reason: "unreachable" });
  });

  it("holds the lookup to the same 5 second deadline as the fetch", { timeout: 5_000 }, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const { transport, pinned } = recordingTransport();
    let answer: ((addresses: { address: string; family: number }[]) => void) | undefined;
    const f = guarded(() => new Promise((resolve) => (answer = resolve)), transport);
    const pending = f.fetch(CLIENT_ID);
    t.mock.timers.tick(4_999);
    t.mock.timers.tick(1);
    assert.deepEqual(await pending, { ok: false, reason: "unreachable" });
    // A lookup that answers after the deadline starts no connection.
    answer!([{ address: "93.184.215.14", family: 4 }]);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(pinned.length, 0);
  });

  it("maps a transport refusal through unchanged", async () => {
    const f = guarded(async () => [{ address: "93.184.215.14", family: 4 }], {
      port: 0,
      request: (options, callback) => httpRequest({ ...options, port: 1, lookup: (_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }]) }, callback),
    });
    assert.deepEqual(await f.fetch(CLIENT_ID), { ok: false, reason: "unreachable" });
  });
});
