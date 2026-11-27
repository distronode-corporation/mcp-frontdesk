// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * `createFrontdesk`: one configured authorization server and resource gate.
 */
import { createAuthorize } from "./authorize.ts";
import { resolveConfig, type FrontdeskConfig } from "./config.ts";
import { createContext } from "./context.ts";
import { authorizationServerMetadata, createDiscovery, protectedResourceMetadata, protectedResourceMetadataUrl } from "./discovery.ts";
import { createGate } from "./gate.ts";
import type { Transport } from "./pinned-get.ts";
import type { GrantSummary } from "./stores.ts";
import { createTokenEndpoint } from "./token-endpoint.ts";

export type Frontdesk = ReturnType<typeof createFrontdeskWith>;

/** Internal: the package's own tests pass a transport. */
export function createFrontdeskWith(config: FrontdeskConfig, internal: { transport?: Transport }) {
  const resolved = resolveConfig(config);
  const ctx = createContext(config, resolved, internal.transport);
  const authorize = createAuthorize(ctx);
  const gate = createGate(ctx);

  return {
    /** The checked configuration, defaults filled in. */
    config: resolved,

    /** The RFC 8414 document. */
    authorizationServerMetadata: () => authorizationServerMetadata(resolved),
    /** The RFC 9728 document. */
    protectedResourceMetadata: () => protectedResourceMetadata(resolved),
    /** The URL the 401 challenge names. */
    protectedResourceMetadataUrl: protectedResourceMetadataUrl(resolved.resource),
    /** Serves both discovery documents; null for any other path. */
    handleDiscovery: createDiscovery(resolved),

    /** Check an authorization request, for the host's consent page. */
    checkAuthorizeRequest: authorize.check,
    /** After the host's consent page says yes: check again, mint a single-use code, answer the redirect URL. */
    approve: authorize.approve,
    /** After the host's consent page says no: the `access_denied` redirect URL. */
    denialUrl: authorize.denialUrl,

    /** The token endpoint. */
    handleToken: createTokenEndpoint(ctx),

    /** The subject's live connections, one per grant family. */
    listGrants: (subject: string): Promise<GrantSummary[]> => config.grantStore.listByUser(subject, new Date(resolved.now())),
    /**
     * Disconnect one connection of the subject's. True when something was
     * revoked. Effective at the next refresh: an access token already minted
     * lives out its lifetime.
     */
    async revokeGrant(subject: string, familyId: string): Promise<boolean> {
      const grants = await config.grantStore.listByUser(subject, new Date(resolved.now()));
      const grant = grants.find((g) => g.familyId === familyId);
      const revoked = await config.grantStore.revokeFamilyForUser(subject, familyId, new Date(resolved.now()));
      if (revoked > 0 && grant) {
        await ctx.audit({ type: "grant.revoked", subject, clientId: grant.clientId, familyId, reason: "user" });
      }
      return revoked > 0;
    },

    /** The bearer gate for the MCP server. */
    authenticate: gate.authenticate,
    /** The 401 challenge, for a host that refuses a request on its own. */
    unauthorized: gate.unauthorized,
    /** The 403 step-up challenge. */
    insufficientScope: gate.insufficientScope,
  };
}

/** Build a Frontdesk. Throws FrontdeskConfigError for a config that is not usable. */
export function createFrontdesk(config: FrontdeskConfig): Frontdesk {
  return createFrontdeskWith(config, {});
}
