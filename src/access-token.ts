/**
 * Access tokens: RFC 9068 JWTs (`typ: at+jwt`), ES256, one audience (the
 * resource), short-lived.
 *
 * Claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `client_id` and `scope`,
 * plus whatever `accessTokenClaims` adds. No email by default: a token is a
 * bearer credential that ends up in logs and client storage, so personal data
 * goes in only when the host asks for it.
 *
 * Verification pins every value it can: the algorithm, `typ`, the kid (no
 * "try the only key" for a token without one), issuer, exactly one audience,
 * `exp`, a maximum age equal to the configured lifetime whatever `exp` says, an
 * `iat` not in the future, and scopes this resource defines. Null is the only
 * failure signal: there is no difference between expired, forged and wrong
 * audience for the caller to leak.
 */
import { SignJWT, decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";

import type { GrantInfo, ResolvedConfig } from "./config.ts";
import { ACCESS_TOKEN_ALG, type KeyProvider } from "./keys.ts";

export const ACCESS_TOKEN_TYP = "at+jwt";

/** Clock tolerance on `exp` and `iat`, in seconds. */
const CLOCK_TOLERANCE_SECONDS = 5;

/** Claims a hook may not set, because the verifier or the protocol owns them. */
export const REGISTERED_CLAIMS: ReadonlySet<string> = new Set(["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "client_id"]);

export interface VerifiedAccessToken {
  subject: string;
  clientId: string;
  scopes: string[];
  tokenId: string;
  /** Seconds since the epoch. */
  issuedAt: number;
  /** Seconds since the epoch. */
  expiresAt: number;
  /** The whole verified payload, custom claims included. */
  claims: JWTPayload;
}

export class NoSigningKeyError extends Error {
  constructor() {
    super("No signing key is available: access tokens cannot be minted");
    this.name = "NoSigningKeyError";
  }
}

export async function mintAccessToken(
  config: ResolvedConfig,
  keys: KeyProvider,
  grant: GrantInfo,
  extraClaims: Record<string, unknown>,
): Promise<string> {
  for (const name of Object.keys(extraClaims)) {
    if (REGISTERED_CLAIMS.has(name)) throw new TypeError(`accessTokenClaims may not set the registered claim "${name}"`);
  }
  if (grant.scopes.length === 0 || grant.scopes.some((scope) => !config.scopes.includes(scope))) {
    throw new TypeError("Refusing to mint an access token with no scope or an unknown one");
  }
  const key = await keys.signingKey();
  if (!key) throw new NoSigningKeyError();
  const now = Math.floor(config.now() / 1000);
  return new SignJWT({ ...extraClaims, client_id: grant.clientId, scope: grant.scopes.join(" ") })
    .setProtectedHeader({ alg: ACCESS_TOKEN_ALG, typ: ACCESS_TOKEN_TYP, kid: key.kid })
    .setIssuer(config.issuer)
    .setSubject(grant.subject)
    .setAudience(config.resource)
    .setIssuedAt(now)
    .setExpirationTime(now + config.accessTtlSeconds)
    .setJti(crypto.randomUUID())
    .sign(key.privateKey);
}

export async function verifyAccessToken(config: ResolvedConfig, keys: KeyProvider, token: string): Promise<VerifiedAccessToken | null> {
  try {
    const kid = decodeProtectedHeader(token).kid;
    if (typeof kid !== "string" || kid === "") return null;
    const key = await keys.verificationKey(kid);
    if (!key) return null;
    const { payload } = await jwtVerify(token, key, {
      algorithms: [ACCESS_TOKEN_ALG],
      typ: ACCESS_TOKEN_TYP,
      issuer: config.issuer,
      audience: config.resource,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      requiredClaims: ["exp", "iat", "jti", "sub"],
      maxTokenAge: config.accessTtlSeconds,
      currentDate: new Date(config.now()),
    });
    // Exactly one audience: jose accepts an array that merely contains ours.
    if (payload.aud !== config.resource) return null;
    const { sub, jti, client_id: clientId, scope, iat, exp } = payload;
    if (typeof sub !== "string" || sub === "" || typeof jti !== "string" || jti === "") return null;
    if (typeof clientId !== "string" || clientId === "") return null;
    const scopes = typeof scope === "string" ? scope.split(" ").filter(Boolean) : [];
    if (scopes.length === 0 || scopes.some((s) => !config.scopes.includes(s))) return null;
    // jwtVerify has refused a missing or non-numeric iat and exp already.
    return { subject: sub, clientId, scopes, tokenId: jti, issuedAt: iat as number, expiresAt: exp as number, claims: payload };
  } catch {
    return null;
  }
}
