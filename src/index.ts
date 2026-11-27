// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * mcp-frontdesk: an OAuth 2.1 authorization server and access-token gate for
 * MCP servers. See README.md.
 */
export { createFrontdesk, type Frontdesk } from "./frontdesk.ts";
export {
  claudeClients,
  DEFAULT_MAX_FAMILY_LIFETIME_SECONDS,
  DEFAULT_TTL,
  FrontdeskConfigError,
  MAX_FAMILY_LIFETIME_SECONDS,
  type AuditEvent,
  type AuditSink,
  type FrontdeskConfig,
  type GrantInfo,
  type RateLimitedEndpoint,
  type RateLimiter,
  type RefreshTokenReusePolicy,
  type Reporter,
  type ResolvedConfig,
  type TokenWrapper,
} from "./config.ts";
export type {
  ApproveParams,
  ApproveResult,
  AuthorizeCheck,
  AuthorizePageError,
  AuthorizeRedirectError,
  AuthorizeRequest,
  RawAuthorizeParams,
} from "./authorize.ts";
export type { VerifiedAccessToken } from "./access-token.ts";
export { bearerTokenFrom, type AuthenticateOptions, type AuthenticateResult } from "./gate.ts";
export { generateSigningJwk, KeyConfigError, keyProviderFromJwk, publicJwk, type KeyProvider, type SigningKey } from "./keys.ts";
export { MemoryCodeStore, MemoryGrantStore, type MemoryStoreOptions } from "./memory-stores.ts";
export type { HostResolver, ResolvedAddress } from "./ssrf.ts";
export type {
  CodeRecord,
  CodeStore,
  GrantContext,
  GrantRecord,
  GrantStore,
  GrantSummary,
  NewGrant,
  RotateOutcome,
  SpentCode,
} from "./stores.ts";
