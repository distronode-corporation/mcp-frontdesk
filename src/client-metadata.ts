/**
 * Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document):
 * how the authorization server learns who a client is without registering it.
 *
 * The client's `client_id` is an https URL. The server fetches it, reads a small
 * JSON document (`client_id`, `client_name`, `redirect_uris`) and checks the
 * authorization request against it.
 *
 * The fetch goes through the SSRF guard (ssrf.ts) and a pinned GET
 * (pinned-get.ts) by default: name hosts only, resolved once, private ranges
 * refused, connection pinned, no redirects, a 5 second deadline and a 5 KB cap.
 * The deadline is one wall-clock budget for the whole fetch, the DNS lookup and
 * the body included: when it passes, the answer is `unreachable`, whatever is
 * still pending, and its signal aborts the request in flight.
 * A caller-supplied fetch replaces the guard only through the option named
 * `unsafeFetchClientMetadata`; the deadline, the cap and every document check
 * still apply to it, even if it ignores the signal.
 *
 * Never throws for anything the remote side does: every fault is a typed refusal.
 */
import { isRecord } from "./encoding.ts";
import { isJsonMediaType, pinnedGet, type PinnedGetResult, type Transport } from "./pinned-get.ts";
import { readCapped } from "./read-capped.ts";
import { resolvePublicAddresses, type HostResolver } from "./ssrf.ts";

/** Wall-clock budget for the whole fetch, body included. */
export const CLIENT_METADATA_TIMEOUT_MS = 5_000;

/** Body cap, the draft's recommendation. */
export const CLIENT_METADATA_MAX_BYTES = 5 * 1024;

const MAX_CLIENT_ID_LENGTH = 512;
const MAX_CLIENT_NAME_LENGTH = 80;
const MAX_REDIRECT_URIS = 10;
const DEFAULT_CACHE_TTL_MS = 5 * 60_000;
const MAX_CACHE_TTL_MS = 60 * 60_000;
const MAX_CACHE_ENTRIES = 100;

export interface ClientMetadata {
  /** The client_id URL, exactly as requested and as the document states it. */
  clientId: string;
  /** Self-asserted by whoever hosts the document. Show it beside the host, never instead of it. */
  clientName: string;
  redirectUris: string[];
}

/** Why a client_id was refused. Logged, never shown beyond `invalid_client`. */
export type ClientMetadataRefusal =
  | "invalid_client_id"
  | "blocked"
  | "unreachable"
  | "http_status"
  | "not_json"
  | "too_large"
  | "invalid_document"
  | "client_id_mismatch"
  | "confidential_client"
  | "invalid_redirect_uris";

export type ClientMetadataResult = { ok: true; metadata: ClientMetadata } | { ok: false; reason: ClientMetadataRefusal };

/**
 * Is `raw` an acceptable client_id URL? Canonical https on the default port,
 * a real path, no userinfo, query or fragment, and a host that is a name, not
 * an IP literal. `href === raw` is the canonical-form check: it refuses dot
 * segments, an explicit `:443`, upper case and stray whitespace, all of which
 * would make the URL fetched differ from the string compared with the
 * document's `client_id`.
 */
export function isValidClientIdUrl(raw: string): boolean {
  if (raw.length > MAX_CLIENT_ID_LENGTH) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  return (
    url.href === raw &&
    url.protocol === "https:" &&
    url.username === "" &&
    url.password === "" &&
    url.port === "" &&
    !raw.includes("?") &&
    !raw.includes("#") &&
    url.pathname !== "/" &&
    !/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname) &&
    !url.hostname.startsWith("[")
  );
}

/** A TTL in ms from Cache-Control, bounded to [0, one hour]. */
export function cacheTtlMs(cacheControl: string | null): number {
  if (!cacheControl) return DEFAULT_CACHE_TTL_MS;
  const directives = cacheControl.toLowerCase();
  if (/\b(no-store|no-cache|private)\b/.test(directives)) return 0;
  const maxAge = /\bmax-age=(\d+)/.exec(directives);
  if (!maxAge) return DEFAULT_CACHE_TTL_MS;
  return Math.min(Number(maxAge[1]) * 1000, MAX_CACHE_TTL_MS);
}

export interface ClientMetadataOptions {
  /** Is this URI one a document may list? (client-policy.ts `isAllowedRedirectUri`, configured.) */
  isAllowedRedirectUri: (uri: string) => boolean;
  resolveHost: HostResolver;
  unsafeFetch: ((url: string, init: { signal: AbortSignal }) => Promise<Response>) | undefined;
  now: () => number;
  /** Internal, for the package's own tests. */
  transport?: Transport | undefined;
}

type FetchOutcome = PinnedGetResult | { ok: false; reason: "blocked" };

/**
 * Run `get` under one deadline of `ms`: its signal aborts when the time is up,
 * and the answer is then `unreachable` even if `get` never settles.
 */
function underDeadline(ms: number, get: (signal: AbortSignal) => Promise<FetchOutcome>): Promise<FetchOutcome> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<FetchOutcome>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve({ ok: false, reason: "unreachable" });
    }, ms);
  });
  return Promise.race([get(controller.signal), expired]).finally(() => clearTimeout(timer));
}

/** The fetcher, with a small per-instance cache of good documents. */
export class ClientMetadataFetcher {
  readonly #options: ClientMetadataOptions;
  readonly #cache = new Map<string, { metadata: ClientMetadata; expiresAt: number }>();

  constructor(options: ClientMetadataOptions) {
    this.#options = options;
  }

  /**
   * Fetch and validate the document at `clientId`. Good documents are cached
   * (Cache-Control respected, at most an hour); refusals are never cached.
   */
  async fetch(clientId: string): Promise<ClientMetadataResult> {
    if (!isValidClientIdUrl(clientId)) return { ok: false, reason: "invalid_client_id" };
    const now = this.#options.now();
    const hit = this.#cache.get(clientId);
    if (hit && hit.expiresAt > now) return { ok: true, metadata: hit.metadata };
    this.#cache.delete(clientId);

    const fetched = await underDeadline(CLIENT_METADATA_TIMEOUT_MS, (signal) =>
      this.#options.unsafeFetch ? this.#unsafeGet(clientId, signal) : this.#guardedGet(clientId, signal),
    );
    if (!fetched.ok) return fetched;

    let doc: unknown;
    try {
      doc = JSON.parse(Buffer.from(fetched.body).toString("utf8"));
    } catch {
      return { ok: false, reason: "not_json" };
    }
    const result = this.#validate(doc, clientId);
    const ttl = cacheTtlMs(fetched.cacheControl);
    if (result.ok && ttl > 0) {
      if (this.#cache.size >= MAX_CACHE_ENTRIES) this.#cache.delete(this.#cache.keys().next().value as string);
      this.#cache.set(clientId, { metadata: result.metadata, expiresAt: now + ttl });
    }
    return result;
  }

  async #guardedGet(clientId: string, signal: AbortSignal): Promise<FetchOutcome> {
    const url = new URL(clientId);
    const guard = await resolvePublicAddresses(url.hostname, this.#options.resolveHost);
    if (!guard.ok) return { ok: false, reason: guard.reason === "blocked" ? "blocked" : "unreachable" };
    // A lookup that answered after the deadline finds the signal aborted, and pinnedGet starts nothing.
    return pinnedGet(url, guard.addresses, { signal, maxBytes: CLIENT_METADATA_MAX_BYTES }, this.#options.transport);
  }

  async #unsafeGet(clientId: string, signal: AbortSignal): Promise<PinnedGetResult> {
    try {
      const res = await this.#options.unsafeFetch!(clientId, { signal });
      const contentType = res.headers.get("content-type");
      if (res.status !== 200 || !isJsonMediaType(contentType)) {
        await res.body?.cancel().catch(() => undefined);
        return { ok: false, reason: res.status !== 200 ? "http_status" : "not_json" };
      }
      const read = await readCapped(res.body, CLIENT_METADATA_MAX_BYTES, res.headers.get("content-length"));
      if (!read.ok) return { ok: false, reason: "too_large" };
      return { ok: true, contentType, cacheControl: res.headers.get("cache-control"), body: read.bytes };
    } catch {
      return { ok: false, reason: "unreachable" };
    }
  }

  #validate(doc: unknown, clientId: string): ClientMetadataResult {
    if (!isRecord(doc)) return { ok: false, reason: "invalid_document" };
    if (doc.client_id !== clientId) return { ok: false, reason: "client_id_mismatch" };
    // A public client only: no secret, and no auth method but `none`.
    if (
      doc.client_secret !== undefined ||
      doc.client_secret_expires_at !== undefined ||
      (doc.token_endpoint_auth_method !== undefined && doc.token_endpoint_auth_method !== "none")
    ) {
      return { ok: false, reason: "confidential_client" };
    }
    const name = typeof doc.client_name === "string" ? doc.client_name.trim() : "";
    if (!name || name.length > MAX_CLIENT_NAME_LENGTH || /\p{Cc}/u.test(name)) {
      return { ok: false, reason: "invalid_document" };
    }
    const uris = doc.redirect_uris;
    if (
      !Array.isArray(uris) ||
      uris.length === 0 ||
      uris.length > MAX_REDIRECT_URIS ||
      !uris.every((uri): uri is string => typeof uri === "string" && this.#options.isAllowedRedirectUri(uri))
    ) {
      return { ok: false, reason: "invalid_redirect_uris" };
    }
    return { ok: true, metadata: { clientId, clientName: name, redirectUris: [...uris] } };
  }
}
