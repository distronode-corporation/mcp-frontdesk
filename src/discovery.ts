/**
 * The two discovery documents, and the handler that serves them:
 *
 *   - RFC 9728 Protected Resource Metadata, at
 *     `/.well-known/oauth-protected-resource<resource path>` (the path-inserted
 *     form the 401 challenge names) and at the root form, which clients try
 *     second;
 *   - RFC 8414 Authorization Server Metadata, at
 *     `/.well-known/oauth-authorization-server<issuer path>`.
 *
 * Both are public, cacheable for an hour, readable from any origin (nothing in
 * them is per-user, and no credential is accepted with them), and pinned to
 * `application/json`.
 */
import { OFFLINE_ACCESS, type ResolvedConfig } from "./config.ts";

const PRM = "/.well-known/oauth-protected-resource";
const ASM = "/.well-known/oauth-authorization-server";

function pathOf(url: string): string {
  const path = new URL(url).pathname;
  return path === "/" ? "" : path;
}

/** The URL the 401 challenge names: the path-inserted form. */
export function protectedResourceMetadataUrl(resource: string): string {
  return `${new URL(resource).origin}${PRM}${pathOf(resource)}`;
}

export function authorizationServerMetadataUrl(issuer: string): string {
  return `${new URL(issuer).origin}${ASM}${pathOf(issuer)}`;
}

export function protectedResourceMetadata(config: ResolvedConfig): Record<string, unknown> {
  return {
    resource: config.resource,
    // One entry: clients use the first and do not fall back.
    authorization_servers: [config.issuer],
    // offline_access is absent on purpose: a resource should not list it.
    scopes_supported: [...config.scopes],
    // The Authorization header only: MCP forbids tokens in the query string.
    bearer_methods_supported: ["header"],
    ...(config.resourceName === undefined ? {} : { resource_name: config.resourceName }),
  };
}

export function authorizationServerMetadata(config: ResolvedConfig): Record<string, unknown> {
  return {
    issuer: config.issuer,
    authorization_endpoint: config.authorizationEndpoint,
    token_endpoint: config.tokenEndpoint,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    // "none" and the CIMD flag together: a client uses a Client ID Metadata
    // Document only when both are advertised. There is no registration_endpoint.
    token_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: true,
    scopes_supported: [...config.scopes, OFFLINE_ACCESS],
    authorization_response_iss_parameter_supported: true,
  };
}

export function createDiscovery(config: ResolvedConfig) {
  const prmPaths = new Set([new URL(protectedResourceMetadataUrl(config.resource)).pathname, PRM]);
  const asmPath = new URL(authorizationServerMetadataUrl(config.issuer)).pathname;

  /** The discovery response for `request`, or null when its path is not a discovery path. */
  return function handleDiscovery(request: Request): Response | null {
    const path = new URL(request.url).pathname;
    const body = prmPaths.has(path) ? protectedResourceMetadata(config) : path === asmPath ? authorizationServerMetadata(config) : null;
    if (body === null) return null;
    const headers = {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers, "Access-Control-Allow-Methods": "GET" } });
    if (request.method !== "GET" && request.method !== "HEAD") {
      return Response.json({ error: "method_not_allowed" }, { status: 405, headers: { Allow: "GET, HEAD, OPTIONS" } });
    }
    return new Response(request.method === "HEAD" ? null : JSON.stringify(body), { status: 200, headers });
  };
}
