import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { base64UrlEncode, isRecord, nonEmptyString, randomToken, sha256Hex } from "../src/encoding.ts";
import { deriveCodeChallenge, isValidCodeChallenge, isValidCodeVerifier } from "../src/pkce.ts";
import { readCapped } from "../src/read-capped.ts";

describe("encoding", () => {
  it("base64url-encodes without padding, including a view into a larger buffer", () => {
    assert.equal(base64UrlEncode(new Uint8Array([0xfb, 0xff, 0xfe])), "-__-");
    assert.equal(base64UrlEncode(new Uint8Array([1])), "AQ");
    const view = new Uint8Array([9, 9, 0xfb, 0xff, 9]).subarray(2, 4);
    assert.equal(base64UrlEncode(view), "-_8");
  });

  it("mints distinct url-safe tokens of the requested size", () => {
    const a = randomToken();
    assert.match(a, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(a, randomToken());
    assert.equal(randomToken(3).length, 4);
  });

  it("hashes to lower-case hex SHA-256", () => {
    assert.equal(sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("tells plain objects and non-empty strings apart", () => {
    assert.equal(isRecord({}), true);
    for (const value of [null, [], "x", 1, undefined]) assert.equal(isRecord(value), false);
    assert.equal(nonEmptyString("a"), true);
    for (const value of ["", 1, null]) assert.equal(nonEmptyString(value), false);
  });
});

describe("PKCE", () => {
  it("derives the RFC 7636 appendix B challenge", () => {
    assert.equal(deriveCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("accepts verifiers of 43 to 128 unreserved characters only", () => {
    assert.equal(isValidCodeVerifier("a".repeat(43)), true);
    assert.equal(isValidCodeVerifier(`${"A-._~".repeat(25)}abc`), true);
    for (const bad of ["a".repeat(42), "a".repeat(129), `${"a".repeat(42)}+`, `${"a".repeat(42)} `]) {
      assert.equal(isValidCodeVerifier(bad), false, bad);
    }
  });

  it("accepts only 43-character base64url challenges", () => {
    assert.equal(isValidCodeChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), true);
    for (const bad of ["E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=", `${"a".repeat(42)}.`]) {
      assert.equal(isValidCodeChallenge(bad), false, bad);
    }
  });
});

/** A stream that serves `chunk` forever and counts how many chunks were pulled. */
function endless(chunk: Uint8Array) {
  const state = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        state.pulled += 1;
        controller.enqueue(chunk);
      },
      cancel() {
        state.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, state };
}

describe("readCapped (safety property 2: streaming caps)", () => {
  it("refuses a declared length over the cap before reading a byte, and cancels the stream", async () => {
    const { stream, state } = endless(new Uint8Array(10));
    assert.deepEqual(await readCapped(stream, 100, "101"), { ok: false, reason: "too_large" });
    assert.equal(state.pulled, 0);
    assert.equal(state.cancelled, true);
  });

  it("stops at the first chunk that crosses the cap of an endless body", async () => {
    const { stream, state } = endless(new Uint8Array(10));
    assert.deepEqual(await readCapped(stream, 95), { ok: false, reason: "too_large" });
    assert.equal(state.pulled, 10);
    assert.equal(state.cancelled, true);
  });

  it("catches a declared length that lies", async () => {
    const { stream } = endless(new Uint8Array(10));
    assert.deepEqual(await readCapped(stream, 50, "5"), { ok: false, reason: "too_large" });
  });

  it("returns a body of exactly the cap, joined from its chunks", async () => {
    const res = new Response(new Blob([new Uint8Array([1, 2]), new Uint8Array([3])]));
    const read = await readCapped(res.body, 3, "not-a-number");
    assert.deepEqual(read, { ok: true, bytes: new Uint8Array([1, 2, 3]) });
  });

  it("reads no body as empty, and refuses a declared length even with no body", async () => {
    assert.deepEqual(await readCapped(null, 10), { ok: true, bytes: new Uint8Array(0) });
    assert.deepEqual(await readCapped(null, 10, "11"), { ok: false, reason: "too_large" });
  });

  it("ignores a cancel that rejects", async () => {
    const failing = () =>
      new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new Uint8Array(10));
        },
        cancel() {
          throw new Error("cancel failed");
        },
      });
    assert.deepEqual(await readCapped(failing(), 5), { ok: false, reason: "too_large" });
    assert.deepEqual(await readCapped(failing(), 5, "6"), { ok: false, reason: "too_large" });
  });
});
