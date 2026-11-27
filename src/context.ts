// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * What every part of one Frontdesk instance shares: the checked config, the
 * host's adapters, and safe wrappers around the optional hooks.
 */
import { ClientMetadataFetcher } from "./client-metadata.ts";
import { isAllowedRedirectUri } from "./client-policy.ts";
import type { AuditEvent, FrontdeskConfig, ResolvedConfig } from "./config.ts";
import type { Transport } from "./pinned-get.ts";
import { systemResolver } from "./ssrf.ts";

export interface Context {
  config: ResolvedConfig;
  hooks: FrontdeskConfig;
  clientMetadata: ClientMetadataFetcher;
  /** Report an internal fault. Never throws. */
  report(where: string, err: unknown): void;
  /** Record an audit event. Never throws; a failing sink is reported. */
  audit(event: AuditEvent): Promise<void>;
}

export function createContext(hooks: FrontdeskConfig, config: ResolvedConfig, transport?: Transport): Context {
  const report = (where: string, err: unknown): void => {
    try {
      hooks.reporter?.error(where, err);
    } catch {
      // A reporter that throws must not turn a refusal into a crash.
    }
  };
  return {
    config,
    hooks,
    clientMetadata: new ClientMetadataFetcher({
      isAllowedRedirectUri: (uri) => isAllowedRedirectUri(uri, config.redirectUris, config.allowLoopbackRedirects),
      resolveHost: hooks.clientMetadata?.resolveHost ?? systemResolver,
      unsafeFetch: hooks.clientMetadata?.unsafeFetchClientMetadata,
      now: config.now,
      transport,
    }),
    report,
    async audit(event) {
      try {
        await hooks.audit?.record(event);
      } catch (err) {
        report("audit", err);
      }
    },
  };
}
