// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Small encoding helpers shared by the rest of the package.
 */
import { createHash, randomBytes } from "node:crypto";

/** A plain object: non-null, not an array. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** base64url without padding (RFC 4648 section 5), the encoding RFC 7636 uses for PKCE. */
export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}

/** A fresh opaque token: `byteLength` bytes from the CSPRNG, base64url encoded. */
export function randomToken(byteLength = 32): string {
  return randomBytes(byteLength).toString("base64url");
}

/** Lower-case hex SHA-256 of a UTF-8 string. Stores only ever see this, never a token. */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** A non-empty string. */
export function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}
