// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Property tests (fast-check) over the parsers that see untrusted input: the client
// metadata document a client_id URL serves, the Cache-Control header that comes with it,
// and the PKCE code_challenge an authorization request carries.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import fc from "fast-check";

import { cacheTtlMs, ClientMetadataFetcher, type ClientMetadataRefusal } from "../src/client-metadata.ts";
import { isAllowedRedirectUri } from "../src/client-policy.ts";
import { deriveCodeChallenge, isValidCodeChallenge, isValidCodeVerifier } from "../src/pkce.ts";
import { CLIENT_ID, clock, HOSTED_REDIRECT, LOOPBACK_REDIRECT } from "./helpers.ts";

const REFUSALS: readonly ClientMetadataRefusal[] = [
  "invalid_client_id",
  "blocked",
  "unreachable",
  "http_status",
  "not_json",
  "too_large",
  "invalid_document",
  "client_id_mismatch",
  "confidential_client",
  "invalid_redirect_uris",
];

const allowed = (uri: string) => isAllowedRedirectUri(uri, [HOSTED_REDIRECT], true);

// Documents near the valid one, so most runs get past JSON parsing into the field checks.
const nearDocument = fc.record(
  {
    client_id: fc.oneof(fc.constant(CLIENT_ID), fc.string(), fc.jsonValue()),
    client_name: fc.oneof(fc.string(), fc.constant("Example Client"), fc.jsonValue()),
    redirect_uris: fc.oneof(
      fc.array(fc.oneof(fc.constantFrom(HOSTED_REDIRECT, LOOPBACK_REDIRECT), fc.string(), fc.jsonValue()), { maxLength: 12 }),
      fc.jsonValue(),
    ),
    token_endpoint_auth_method: fc.oneof(fc.constant("none"), fc.string()),
    client_secret: fc.string(),
  },
  { requiredKeys: [] },
);

// Documents that are mostly valid, so the success path and its invariants are reached too.
const mostlyValidDocument = fc.record(
  {
    client_id: fc.constant(CLIENT_ID),
    client_name: fc.string({ minLength: 1, maxLength: 90 }),
    redirect_uris: fc.array(fc.constantFrom(HOSTED_REDIRECT, LOOPBACK_REDIRECT), { maxLength: 11 }),
    token_endpoint_auth_method: fc.constantFrom("none", "client_secret_basic"),
  },
  { requiredKeys: ["client_id", "client_name", "redirect_uris"] },
);

const body = fc.oneof(
  { arbitrary: mostlyValidDocument.map((doc) => JSON.stringify(doc)), weight: 3 },
  nearDocument.map((doc) => JSON.stringify(doc)),
  fc.jsonValue().map((value) => JSON.stringify(value)),
  fc.string(),
  fc.uint8Array({ maxLength: 6 * 1024 }),
);

describe("property: a client metadata document", () => {
  it("never makes fetch throw: the answer is valid metadata or a typed refusal", async () => {
    await fc.assert(
      fc.asyncProperty(
        body,
        fc.constantFrom(200, 200, 200, 200, 200, 301, 404, 500),
        fc.constantFrom("application/json", "application/json", "application/json; charset=utf-8", "text/html", ""),
        fc.constantFrom(null, "no-store", "max-age=60", "max-age=99999999999", "private, max-age=5"),
        async (payload, status, contentType, cacheControl) => {
          const headers = new Headers();
          if (contentType) headers.set("content-type", contentType);
          if (cacheControl) headers.set("cache-control", cacheControl);
          const fetcher = new ClientMetadataFetcher({
            isAllowedRedirectUri: allowed,
            resolveHost: async () => {
              throw new Error("the resolver must not be asked when an unsafe fetch is set");
            },
            unsafeFetch: async () => new Response(payload, { status, headers }),
            now: clock().now,
          });
          const result = await fetcher.fetch(CLIENT_ID);
          if (!result.ok) {
            assert.ok(REFUSALS.includes(result.reason), result.reason);
            return;
          }
          const { metadata } = result;
          assert.equal(metadata.clientId, CLIENT_ID);
          assert.ok(metadata.clientName.length > 0 && metadata.clientName.length <= 80);
          assert.equal(metadata.clientName, metadata.clientName.trim());
          assert.ok(!/\p{Cc}/u.test(metadata.clientName));
          assert.ok(metadata.redirectUris.length >= 1 && metadata.redirectUris.length <= 10);
          for (const uri of metadata.redirectUris) assert.ok(allowed(uri), uri);
        },
      ),
      { numRuns: 300 },
    );
  });
});

describe("property: cacheTtlMs", () => {
  it("is a whole number of ms between 0 and one hour for any header value", () => {
    fc.assert(
      fc.property(
        fc.option(
          fc.oneof(
            fc.string(),
            fc.nat().map((n) => `max-age=${n}`),
            fc.bigInt({ min: 0n, max: 10n ** 40n }).map((n) => `public, max-age=${n}`),
          ),
        ),
        (header) => {
          const ttl = cacheTtlMs(header);
          assert.ok(Number.isInteger(ttl), String(ttl));
          assert.ok(ttl >= 0 && ttl <= 60 * 60_000, String(ttl));
        },
      ),
      { numRuns: 500 },
    );
  });
});

describe("property: PKCE", () => {
  const verifier = fc.string({
    unit: fc.constantFrom(..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"),
    minLength: 43,
    maxLength: 128,
  });

  it("the S256 challenge of every valid verifier passes the challenge check and round-trips as a 32-byte digest", () => {
    fc.assert(
      fc.property(verifier, (v) => {
        assert.ok(isValidCodeVerifier(v));
        const challenge = deriveCodeChallenge(v);
        assert.ok(isValidCodeChallenge(challenge), v);
        const bytes = Buffer.from(challenge, "base64url");
        assert.equal(bytes.length, 32);
        assert.equal(bytes.toString("base64url"), challenge);
      }),
      { numRuns: 500 },
    );
  });
});
