// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * One HTTPS GET, connected to addresses the SSRF guard already checked.
 *
 *   - The socket's DNS lookup answers with the pinned addresses only, so the
 *     name cannot be re-resolved to something else at connect time. TLS still
 *     verifies the certificate against the host name (SNI and Host are the name).
 *   - Redirects are never followed: `https.request` does not follow them, and
 *     any status other than 200 is a refusal.
 *   - The caller's deadline (an AbortSignal) covers connect, headers and body:
 *     when it fires, the request is destroyed, and an already-fired one starts
 *     nothing.
 *   - The body is capped while streaming: a declared length over the cap is
 *     refused before reading, and the socket is destroyed at the first chunk
 *     that crosses it.
 *   - No connection pooling (`agent: false`), so nothing is reused across names.
 */
import type { IncomingMessage, RequestOptions, ClientRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { LookupFunction } from "node:net";

import type { ResolvedAddress } from "./ssrf.ts";

export interface PinnedGetLimits {
  /** The deadline. Aborting it ends the request as `unreachable`. */
  signal: AbortSignal;
  maxBytes: number;
}

export type PinnedGetResult =
  | { ok: true; contentType: string | null; cacheControl: string | null; body: Uint8Array }
  | { ok: false; reason: "unreachable" | "http_status" | "not_json" | "too_large" };

/**
 * How the request is made. Internal: production always uses `https.request` on
 * port 443. The package's own tests pass `http.request` and a local port to
 * exercise pinning, the deadline and the cap without certificates.
 */
export interface Transport {
  request: (options: RequestOptions, callback: (res: IncomingMessage) => void) => ClientRequest;
  port: number;
}

const httpsTransport: Transport = { request: httpsRequest, port: 443 };

/** `application/json` or `application/<x>+json`, parameters ignored. */
export function isJsonMediaType(contentType: string | null | undefined): boolean {
  const media = (contentType ?? "").split(";")[0]!.trim().toLowerCase();
  return /^application\/([a-z0-9.-]+\+)?json$/.test(media);
}

export function pinnedLookup(addresses: readonly ResolvedAddress[]): LookupFunction {
  return (_hostname, options, callback) => {
    if (options.all) {
      callback(null, addresses.map((entry) => ({ address: entry.address, family: entry.family })));
    } else {
      const first = addresses[0]!;
      callback(null, first.address, first.family);
    }
  };
}

export function pinnedGet(
  url: URL,
  addresses: readonly ResolvedAddress[],
  limits: PinnedGetLimits,
  transport: Transport = httpsTransport,
): Promise<PinnedGetResult> {
  return new Promise((resolve) => {
    if (limits.signal.aborted) return resolve({ ok: false, reason: "unreachable" });
    let settled = false;
    let req: ClientRequest | undefined;
    const onAbort = () => finish({ ok: false, reason: "unreachable" });
    const finish = (result: PinnedGetResult) => {
      if (settled) return;
      settled = true;
      limits.signal.removeEventListener("abort", onAbort);
      req?.destroy();
      resolve(result);
    };
    limits.signal.addEventListener("abort", onAbort, { once: true });

    req = transport.request(
      {
        method: "GET",
        host: url.hostname,
        port: transport.port,
        path: url.pathname,
        headers: { Accept: "application/json" },
        lookup: pinnedLookup(addresses),
        agent: false,
      },
      (res) => {
        if (res.statusCode !== 200) return finish({ ok: false, reason: "http_status" });
        const contentType = res.headers["content-type"] ?? null;
        if (!isJsonMediaType(contentType)) return finish({ ok: false, reason: "not_json" });
        const declared = Number(res.headers["content-length"]);
        if (Number.isFinite(declared) && declared > limits.maxBytes) return finish({ ok: false, reason: "too_large" });
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          total += chunk.byteLength;
          if (total > limits.maxBytes) return finish({ ok: false, reason: "too_large" });
          chunks.push(chunk);
        });
        res.on("end", () => {
          const cacheControl = res.headers["cache-control"] ?? null;
          finish({ ok: true, contentType, cacheControl, body: new Uint8Array(Buffer.concat(chunks)) });
        });
        res.on("error", () => finish({ ok: false, reason: "unreachable" }));
      },
    );
    req.on("error", () => finish({ ok: false, reason: "unreachable" }));
    req.end();
  });
}
