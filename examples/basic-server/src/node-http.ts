// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * The small adapter between `node:http` and the Web `Request` and `Response`
 * that mcp-frontdesk and the MCP SDK's handler speak.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

/**
 * A Web Request for `req`. The URL is built from the server's own origin, never
 * from the Host header, and the body streams (nothing is buffered here).
 * Null for a request target that is not a path (`GET http://other/ HTTP/1.1`).
 */
export function toWebRequest(req: IncomingMessage, origin: string, signal: AbortSignal): Request | null {
  if (!req.url?.startsWith("/") || req.url.startsWith("//")) return null;
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const entry of Array.isArray(value) ? value : [value]) headers.append(name, entry);
  }
  const method = req.method ?? "GET";
  const hasBody = method !== "GET" && method !== "HEAD";
  return new Request(`${origin}${req.url}`, {
    method,
    headers,
    signal,
    ...(hasBody ? { body: Readable.toWeb(req) as ReadableStream<Uint8Array>, duplex: "half" } : {}),
  } as RequestInit);
}

/** Write a Web Response to `res`, streaming its body (an MCP response may be an event stream). */
export async function sendWebResponse(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, name) => {
    if (name !== "set-cookie") res.setHeader(name, value);
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) res.setHeader("set-cookie", cookies);
  if (!response.body) {
    res.end();
    return;
  }
  try {
    await pipeline(Readable.fromWeb(response.body as import("node:stream/web").ReadableStream), res);
  } catch {
    // The client went away mid-stream; nothing left to answer.
  }
}

/** Read a small form body, stopping at `maxBytes` instead of buffering whatever arrives. */
export async function readForm(request: Request, maxBytes: number): Promise<URLSearchParams | null> {
  const type = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (type !== "application/x-www-form-urlencoded" || !request.body) return null;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}
