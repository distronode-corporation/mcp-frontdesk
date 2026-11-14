import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { SignJWT, decodeJwt, decodeProtectedHeader, generateKeyPair, type CryptoKey } from "jose";

import { mintAccessToken, NoSigningKeyError, verifyAccessToken } from "../src/access-token.ts";
import type { GrantInfo } from "../src/config.ts";
import { generateSigningJwk, KeyConfigError, keyProviderFromJwk, publicJwk, readEcJwk, type KeyProvider } from "../src/keys.ts";
import { harness, ISSUER, RESOURCE, testJwk } from "./helpers.ts";

const GRANT: GrantInfo = {
  subject: "user-1",
  clientId: "https://client.example.com/oauth/metadata.json",
  scopes: ["notes:read"],
  context: {},
  familyId: "fam-1",
  authorizedAt: new Date(0),
};

describe("readEcJwk", () => {
  it("accepts a P-256 private key, and its public half for verification", async () => {
    const jwk = await testJwk();
    assert.equal(readEcJwk(jwk, true).kid, "test-key");
    assert.equal(readEcJwk(publicJwk(jwk), false).d, undefined);
  });

  const cases: [string, (jwk: Record<string, unknown>) => unknown, boolean, string][] = [
    ["not an object", () => "nope", true, "the key is not a JSON object"],
    ["another curve", (j) => ({ ...j, crv: "P-384" }), true, "the key is not an EC P-256 key"],
    ["an RSA key", (j) => ({ ...j, kty: "RSA" }), true, "the key is not an EC P-256 key"],
    ["no x", (j) => ({ ...j, x: undefined }), true, "the key has no x and y"],
    ["an empty y", (j) => ({ ...j, y: "" }), true, "the key has no x and y"],
    ["no kid", (j) => ({ ...j, kid: undefined }), true, "the key has no kid"],
    ["alg RS256", (j) => ({ ...j, alg: "RS256" }), true, "the key's alg is not ES256"],
    ["use enc", (j) => ({ ...j, use: "enc" }), true, "the key's use is not sig"],
    ["a public key where a private one is needed", (j) => ({ ...j, d: undefined }), true, "the key is not a private key (no d)"],
    ["private material in a verification key", (j) => j, false, "a verification key holds private key material"],
  ];
  for (const [what, mutate, wantPrivate, message] of cases) {
    it(`refuses ${what}, naming no key material`, async () => {
      const jwk = await testJwk();
      assert.throws(() => readEcJwk(mutate(jwk), wantPrivate), (err: unknown) => {
        assert.ok(err instanceof KeyConfigError);
        assert.equal(err.message, message);
        assert.ok(!err.message.includes(String(jwk.d)));
        return true;
      });
    });
  }
});

describe("keyProviderFromJwk", () => {
  it("signs with the private key and verifies its own kid and the previous keys' kids", async () => {
    const current = await testJwk();
    const old = await generateSigningJwk("old-key");
    const provider = await keyProviderFromJwk(current, { previous: [publicJwk(old)] });
    assert.equal((await provider.signingKey())?.kid, "test-key");
    assert.ok(await provider.verificationKey("test-key"));
    assert.ok(await provider.verificationKey("old-key"));
    assert.equal(await provider.verificationKey("unknown"), null);
  });

  it("refuses two keys under one kid, and coordinates that do not import", async () => {
    const current = await testJwk();
    await assert.rejects(keyProviderFromJwk(current, { previous: [publicJwk(current)] }), /two keys share one kid/);
    await assert.rejects(keyProviderFromJwk({ ...current, x: "AAAA" }), (err: unknown) => err instanceof KeyConfigError && err.message === "the key failed to import");
  });

  it("generates keys with a random kid by default", async () => {
    const a = await generateSigningJwk();
    assert.equal(a.kty, "EC");
    assert.equal(a.crv, "P-256");
    assert.equal(a.alg, "ES256");
    assert.equal(a.use, "sig");
    assert.match(String(a.kid), /^[A-Za-z0-9_-]{16}$/);
    assert.ok(a.d);
  });
});

async function mint(keys: KeyProvider, extra: Record<string, unknown> = {}, grant: GrantInfo = GRANT) {
  const h = await harness({ keys });
  return { h, token: await mintAccessToken(h.fd.config, keys, grant, extra) };
}

describe("mintAccessToken", () => {
  it("mints an RFC 9068 token with no email and every registered claim (safety property 5)", async () => {
    const h = await harness();
    const token = await mintAccessToken(h.fd.config, h.keys, GRANT, {});
    assert.deepEqual(decodeProtectedHeader(token), { alg: "ES256", typ: "at+jwt", kid: "test-key" });
    const claims = decodeJwt(token);
    assert.deepEqual(Object.keys(claims).sort(), ["aud", "client_id", "exp", "iat", "iss", "jti", "scope", "sub"]);
    assert.equal(claims.iss, ISSUER);
    assert.equal(claims.aud, RESOURCE);
    assert.equal(claims.sub, "user-1");
    assert.equal(claims.exp! - claims.iat!, 600);
    assert.equal(claims.iat, Math.floor(h.clock.now() / 1000));
    assert.notEqual(decodeJwt(await mintAccessToken(h.fd.config, h.keys, GRANT, {})).jti, claims.jti);
  });

  it("adds custom claims, and refuses every registered one", async () => {
    const h = await harness();
    const token = await mintAccessToken(h.fd.config, h.keys, GRANT, { email: "person@example.com", tenant: "t-1" });
    assert.equal(decodeJwt(token).email, "person@example.com");
    for (const name of ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "client_id"]) {
      await assert.rejects(mintAccessToken(h.fd.config, h.keys, GRANT, { [name]: "x" }), TypeError, name);
    }
  });

  it("refuses no scope or a scope the resource does not define, and a missing key", async () => {
    const h = await harness();
    await assert.rejects(mintAccessToken(h.fd.config, h.keys, { ...GRANT, scopes: [] }, {}), TypeError);
    await assert.rejects(mintAccessToken(h.fd.config, h.keys, { ...GRANT, scopes: ["notes:admin"] }, {}), TypeError);
    const none: KeyProvider = { signingKey: async () => null, verificationKey: async () => null };
    await assert.rejects(mintAccessToken(h.fd.config, none, GRANT, {}), NoSigningKeyError);
  });
});

describe("verifyAccessToken refuses hostile input", () => {
  /** Sign arbitrary claims and header with the real key. */
  async function forge(h: Awaited<ReturnType<typeof harness>>, claims: Record<string, unknown>, header: Record<string, unknown> = {}, key?: CryptoKey) {
    const nowS = Math.floor(h.clock.now() / 1000);
    const privateKey = key ?? (await h.keys.signingKey())!.privateKey;
    return new SignJWT({ iss: ISSUER, aud: RESOURCE, sub: "user-1", client_id: GRANT.clientId, scope: "notes:read", iat: nowS, exp: nowS + 600, jti: "j-1", ...claims })
      .setProtectedHeader({ alg: "ES256", typ: "at+jwt", kid: "test-key", ...header } as never)
      .sign(privateKey);
  }

  it("accepts the reference token the table below varies, and reports its claims", async () => {
    const h = await harness();
    const verified = await verifyAccessToken(h.fd.config, h.keys, await forge(h, { tenant: "t-1" }));
    assert.equal(verified?.subject, "user-1");
    assert.equal(verified?.clientId, GRANT.clientId);
    assert.deepEqual(verified?.scopes, ["notes:read"]);
    assert.equal(verified?.tokenId, "j-1");
    assert.equal(verified?.expiresAt! - verified?.issuedAt!, 600);
    assert.equal(verified?.claims.tenant, "t-1");
  });

  const table: [string, Record<string, unknown>, Record<string, unknown>?][] = [
    ["no kid", {}, { kid: undefined }],
    ["an empty kid", {}, { kid: "" }],
    ["an unknown kid", {}, { kid: "other" }],
    ["typ JWT", {}, { typ: "JWT" }],
    ["another issuer", { iss: "https://evil.example.net" }],
    ["another audience", { aud: "https://mcp.example.com/other" }],
    ["two audiences", { aud: [RESOURCE, "https://other.example.com"] }],
    ["no sub", { sub: undefined }],
    ["an empty sub", { sub: "" }],
    ["no jti", { jti: undefined }],
    ["an empty jti", { jti: "" }],
    ["no client_id", { client_id: undefined }],
    ["an empty client_id", { client_id: "" }],
    ["no scope", { scope: undefined }],
    ["a blank scope", { scope: "  " }],
    ["an unknown scope", { scope: "notes:read notes:admin" }],
    ["no exp", { exp: undefined }],
    ["no iat", { iat: undefined }],
  ];
  for (const [what, claims, header] of table) {
    it(`refuses ${what}`, async () => {
      const h = await harness();
      assert.equal(await verifyAccessToken(h.fd.config, h.keys, await forge(h, claims, header)), null);
    });
  }

  it("refuses a token signed by another key under this key's kid", async () => {
    const h = await harness();
    const { privateKey } = await generateKeyPair("ES256");
    assert.equal(await verifyAccessToken(h.fd.config, h.keys, await forge(h, {}, {}, privateKey)), null);
  });

  it("refuses HS256 under the right kid and typ (no algorithm confusion)", async () => {
    const h = await harness();
    const nowS = Math.floor(h.clock.now() / 1000);
    const hs = await new SignJWT({ iss: ISSUER, aud: RESOURCE, sub: "u", client_id: "c", scope: "notes:read", iat: nowS, exp: nowS + 60, jti: "j" })
      .setProtectedHeader({ alg: "HS256", typ: "at+jwt", kid: "test-key" })
      .sign(new Uint8Array(32));
    assert.equal(await verifyAccessToken(h.fd.config, h.keys, hs), null);
  });

  it("refuses something that is not a JWT at all", async () => {
    const h = await harness();
    for (const junk of ["", "abc", "a.b.c", "eyJhbGciOiJub25lIn0.e30."]) assert.equal(await verifyAccessToken(h.fd.config, h.keys, junk), null, junk);
  });

  it("expires on schedule, with five seconds of tolerance and no more", async () => {
    const h = await harness();
    const token = await mintAccessToken(h.fd.config, h.keys, GRANT, {});
    h.clock.advance(604_000);
    assert.ok(await verifyAccessToken(h.fd.config, h.keys, token));
    h.clock.advance(1_000);
    assert.equal(await verifyAccessToken(h.fd.config, h.keys, token), null);
  });

  it("refuses a token older than the lifetime even when its own exp is far away", async () => {
    const h = await harness();
    const token = await forge(h, { exp: Math.floor(h.clock.now() / 1000) + 86_400 });
    h.clock.advance(606_000);
    assert.equal(await verifyAccessToken(h.fd.config, h.keys, token), null);
  });

  it("refuses an iat in the future", async () => {
    const h = await harness();
    assert.equal(await verifyAccessToken(h.fd.config, h.keys, await forge(h, { iat: Math.floor(h.clock.now() / 1000) + 60 })), null);
  });

  it("a key provider that throws is a refusal, not a crash", async () => {
    const h = await harness();
    const token = await mintAccessToken(h.fd.config, h.keys, GRANT, {});
    const broken: KeyProvider = { signingKey: async () => null, verificationKey: async () => Promise.reject(new Error("down")) };
    assert.equal(await verifyAccessToken(h.fd.config, broken, token), null);
  });

  it("accepts tokens of a previous key during a rotation", async () => {
    const old = await generateSigningJwk("old-key");
    const { token } = await mint(await keyProviderFromJwk(old));
    const rotated = await keyProviderFromJwk(await testJwk(), { previous: [publicJwk(old)] });
    const h = await harness({ keys: rotated });
    assert.ok(await verifyAccessToken(h.fd.config, rotated, token));
  });
});
