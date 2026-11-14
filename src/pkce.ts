/**
 * PKCE (RFC 7636), S256 only. `plain` is never accepted.
 */
import { createHash } from "node:crypto";

/** RFC 7636 section 4.1: 43 to 128 characters from the unreserved set. */
export function isValidCodeVerifier(verifier: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(verifier);
}

/**
 * An S256 challenge is base64url of a 32-byte digest: exactly 43 characters,
 * unpadded. Checking the shape at authorize time means a broken client fails
 * there with a clear error, not later as a verifier mismatch.
 */
export function isValidCodeChallenge(challenge: string): boolean {
  return /^[A-Za-z0-9\-_]{43}$/.test(challenge);
}

/** BASE64URL(SHA256(ASCII(code_verifier))). */
export function deriveCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}
