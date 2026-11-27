// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

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
 * unpadded. 43 characters carry 258 bits, so the last one holds 4 bits of the
 * digest and 2 that are always zero: only 16 of the 64 characters can end a
 * real challenge. Checking the shape at authorize time means a broken client
 * fails there with a clear error, not later as a verifier mismatch, and no
 * code is issued that no verifier could ever redeem.
 */
export function isValidCodeChallenge(challenge: string): boolean {
  return /^[A-Za-z0-9\-_]{42}[AEIMQUYcgkosw048]$/.test(challenge);
}

/** BASE64URL(SHA256(ASCII(code_verifier))). */
export function deriveCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}
