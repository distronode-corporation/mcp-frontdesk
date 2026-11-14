/**
 * The pinned GET against a local plain-HTTP server. The transport is the one
 * internal seam: `http.request` on a local port instead of `https.request` on
 * 443. Everything else (pinning, no redirects, deadline, streaming cap) is the
 * production code path.
 */
import { strict as assert } from "node:assert";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { isJsonMediaType, pinnedGet, pinnedLookup, type Transport } from "../src/pinned-get.ts";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;
let handler: Handler = (_req, res) => res.end();
const seen: { host: string | undefined; path: string | undefined }[] = [];
const server = createServer((req, res) => {
  seen.push({ host: req.headers.host, path: req.url });
  handler(req, res);
});
let transport: Transport;
const LOOPBACK = [{ address: "127.0.0.1", family: 4 }];
const LIMITS = { timeoutMs: 1_000, maxBytes: 64 };

before(async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  transport = { request: httpRequest, port: (server.address() as AddressInfo).port };
});
after(() => {
  server.closeAllConnections();
  server.close();
});

const url = new URL("https://client.example.com/oauth/metadata.json");

describe("pinnedGet", () => {
  it("connects to the pinned address while naming the original host, and returns the body", async () => {
    handler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "max-age=60" });
      res.end('{"ok":true}');
    };
    seen.length = 0;
    const result = await pinnedGet(url, LOOPBACK, LIMITS, transport);
    assert.deepEqual(result, {
      ok: true,
      contentType: "application/json",
      cacheControl: "max-age=60",
      body: new Uint8Array(Buffer.from('{"ok":true}')),
    });
    // client.example.com does not resolve to this machine: only the pin got us here.
    assert.equal(seen[0]?.host, `client.example.com:${transport.port}`);
    assert.equal(seen[0]?.path, "/oauth/metadata.json");
  });

  it("answers a missing Cache-Control as null", async () => {
    handler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    };
    const result = await pinnedGet(url, LOOPBACK, LIMITS, transport);
    assert.equal(result.ok && result.cacheControl, null);
  });

  it("never follows a redirect", async () => {
    handler = (req, res) => {
      if (req.url === "/inside") throw new Error("followed");
      res.writeHead(302, { Location: "/inside" });
      res.end();
    };
    seen.length = 0;
    assert.deepEqual(await pinnedGet(url, LOOPBACK, LIMITS, transport), { ok: false, reason: "http_status" });
    assert.equal(seen.length, 1);
  });

  it("refuses a body that is not JSON, or has no Content-Type", async () => {
    handler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html>");
    };
    assert.deepEqual(await pinnedGet(url, LOOPBACK, LIMITS, transport), { ok: false, reason: "not_json" });
    handler = (_req, res) => {
      res.removeHeader("Content-Type");
      res.writeHead(200);
      res.end("{}");
    };
    assert.deepEqual(await pinnedGet(url, LOOPBACK, LIMITS, transport), { ok: false, reason: "not_json" });
  });

  it("refuses a declared length over the cap before reading", async () => {
    handler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "65" });
      res.end("x".repeat(65));
    };
    assert.deepEqual(await pinnedGet(url, LOOPBACK, LIMITS, transport), { ok: false, reason: "too_large" });
  });

  it("cuts off an endless body at the cap and closes the connection", async () => {
    let written = 0;
    let closed!: () => void;
    const closedPromise = new Promise<void>((resolve) => (closed = resolve));
    handler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      const timer = setInterval(() => {
        written += 32;
        res.write("x".repeat(32));
      }, 5);
      res.on("close", () => {
        clearInterval(timer);
        closed();
      });
    };
    assert.deepEqual(await pinnedGet(url, LOOPBACK, LIMITS, transport), { ok: false, reason: "too_large" });
    await closedPromise;
    assert.ok(written < 64 * 20, `the server kept writing (${written} bytes)`);
  });

  it("gives up at the deadline", async () => {
    handler = () => undefined; // never answers
    const started = Date.now();
    assert.deepEqual(await pinnedGet(url, LOOPBACK, { ...LIMITS, timeoutMs: 100 }, transport), { ok: false, reason: "unreachable" });
    assert.ok(Date.now() - started < 900);
  });

  it("answers unreachable when the body breaks mid-stream", async () => {
    handler = (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write("{");
      setTimeout(() => res.socket?.destroy(), 10);
    };
    assert.deepEqual(await pinnedGet(url, LOOPBACK, LIMITS, transport), { ok: false, reason: "unreachable" });
  });

  it("answers unreachable when nothing listens, through the default https transport", async () => {
    // 127.0.0.1:443 on a test machine: refused, or not a valid certificate for the name. Either is unreachable.
    assert.deepEqual(await pinnedGet(url, LOOPBACK, LIMITS), { ok: false, reason: "unreachable" });
  });
});

describe("pinnedLookup", () => {
  it("answers every pinned address, or the first, never a fresh lookup", () => {
    const lookup = pinnedLookup([
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800::1", family: 6 },
    ]);
    const all: unknown[] = [];
    lookup("evil.example.net", { all: true }, (err, addresses) => all.push(err, addresses));
    assert.deepEqual(all, [
      null,
      [
        { address: "93.184.215.14", family: 4 },
        { address: "2606:2800::1", family: 6 },
      ],
    ]);
    const one: unknown[] = [];
    lookup("evil.example.net", {}, (err, address, family) => one.push(err, address, family));
    assert.deepEqual(one, [null, "93.184.215.14", 4]);
  });
});

describe("isJsonMediaType", () => {
  it("accepts application/json and +json types, parameters and case ignored", () => {
    for (const type of ["application/json", "application/json; charset=utf-8", "APPLICATION/JSON", "application/oauth-client-metadata+json"]) {
      assert.equal(isJsonMediaType(type), true, type);
    }
    for (const type of ["text/json", "application/jsonx", "", null, undefined]) assert.equal(isJsonMediaType(type), false, String(type));
  });
});
