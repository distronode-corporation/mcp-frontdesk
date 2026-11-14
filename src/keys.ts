/**
 * Signing keys for access tokens: ES256 (P-256) only.
 *
 * The host supplies a `KeyProvider`. `keyProviderFromJwk` builds one from a
 * private JWK (plus older public keys still accepted during a rotation), and
 * `generateSigningJwk` makes a fresh key for development and tests.
 *
 * There is deliberately no JWKS endpoint: access tokens are verified by the
 * same server that minted them (see SPEC.md).
 */
import { exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from "jose";

import { isRecord, nonEmptyString, randomToken } from "./encoding.ts";

export const ACCESS_TOKEN_ALG = "ES256";

export interface SigningKey {
  /** Goes in every token's protected header; verification looks the key up by it. */
  kid: string;
  privateKey: CryptoKey;
}

export interface KeyProvider {
  /** The key new tokens are signed with, or null when there is none (the token endpoint then refuses before spending anything). */
  signingKey(): Promise<SigningKey | null>;
  /** The public key for `kid`, or null for a kid this server does not accept. */
  verificationKey(kid: string): Promise<CryptoKey | null>;
}

/** A key that cannot be used. The message names the problem, never key material. */
export class KeyConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyConfigError";
  }
}

interface ReadJwk {
  kid: string;
  pub: { kty: "EC"; crv: "P-256"; x: string; y: string };
  d: string | undefined;
}

/** Check a JWK's shape: EC P-256, x and y, a kid, alg ES256 and use sig when present, d only when wanted. */
export function readEcJwk(value: unknown, wantPrivate: boolean): ReadJwk {
  if (!isRecord(value)) throw new KeyConfigError("the key is not a JSON object");
  const { kty, crv, x, y, d, kid, alg, use } = value;
  if (kty !== "EC" || crv !== "P-256") throw new KeyConfigError("the key is not an EC P-256 key");
  if (!nonEmptyString(x) || !nonEmptyString(y)) throw new KeyConfigError("the key has no x and y");
  if (!nonEmptyString(kid)) throw new KeyConfigError("the key has no kid");
  if (alg !== undefined && alg !== ACCESS_TOKEN_ALG) throw new KeyConfigError("the key's alg is not ES256");
  if (use !== undefined && use !== "sig") throw new KeyConfigError("the key's use is not sig");
  if (wantPrivate && !nonEmptyString(d)) throw new KeyConfigError("the key is not a private key (no d)");
  if (!wantPrivate && d !== undefined) throw new KeyConfigError("a verification key holds private key material");
  return { kid, pub: { kty, crv, x, y }, d: wantPrivate ? (d as string) : undefined };
}

async function importOrThrow(jwk: JWK): Promise<CryptoKey> {
  try {
    return (await importJWK(jwk, ACCESS_TOKEN_ALG)) as CryptoKey;
  } catch {
    // The import error is not echoed, in case it quotes the key.
    throw new KeyConfigError("the key failed to import");
  }
}

/**
 * A KeyProvider over one private JWK and, optionally, older public JWKs whose
 * tokens are still accepted (a rotation: sign with the new key, keep the old
 * public key for one access-token lifetime). Throws KeyConfigError on any bad key.
 */
export async function keyProviderFromJwk(privateJwk: unknown, options: { previous?: readonly unknown[] } = {}): Promise<KeyProvider> {
  const signing = readEcJwk(privateJwk, true);
  const privateKey = await importOrThrow({ ...signing.pub, d: signing.d });
  const verifiers = new Map<string, CryptoKey>([[signing.kid, await importOrThrow(signing.pub)]]);
  for (const old of options.previous ?? []) {
    const read = readEcJwk(old, false);
    if (verifiers.has(read.kid)) throw new KeyConfigError("two keys share one kid");
    verifiers.set(read.kid, await importOrThrow(read.pub));
  }
  const key: SigningKey = { kid: signing.kid, privateKey };
  return {
    signingKey: async () => key,
    verificationKey: async (kid) => verifiers.get(kid) ?? null,
  };
}

/** A fresh P-256 private JWK with a random kid. Store it as a secret; never commit it. */
export async function generateSigningJwk(kid: string = randomToken(12)): Promise<JWK> {
  const { privateKey } = await generateKeyPair(ACCESS_TOKEN_ALG, { extractable: true });
  return { ...(await exportJWK(privateKey)), kid, alg: ACCESS_TOKEN_ALG, use: "sig" };
}

/** The public half of a private JWK, for `previous` after a rotation. */
export function publicJwk(privateJwk: unknown): JWK {
  const read = readEcJwk(privateJwk, true);
  return { ...read.pub, kid: read.kid, alg: ACCESS_TOKEN_ALG, use: "sig" };
}
