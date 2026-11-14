/**
 * Grants: the refresh-token half, over the host's GrantStore.
 *
 *   - Only SHA-256 of a refresh token is stored.
 *   - Every refresh rotates: the presented token is spent and a successor in
 *     the same family is returned (OAuth 2.1 requires rotation for a public
 *     client).
 *   - A rotated token presented again is indistinguishable from theft. By
 *     default the whole family is revoked, successor included
 *     (`refreshTokenReuse: "revoke-family"`). With `"refuse"`, only the
 *     presented token is refused and the successor lives (see SECURITY-MODEL.md
 *     for when that is the better trade).
 *   - The claim is atomic (`GrantStore.rotate`), so two concurrent refreshes of
 *     one token are the same reuse, and a refresh racing a revocation cannot
 *     leave a live successor.
 *   - A live refresh token is bound to its client: presented by another
 *     client_id, the family is revoked whatever the reuse policy. A token
 *     already rotated is reuse first, and the reuse policy decides.
 *   - `isGrantActive` is asked before every rotation; false revokes the family.
 *   - A family has an absolute lifetime, `maxFamilyLifetimeSeconds` from its
 *     first row (`familyCreatedAt`). Each row's sliding expiry is capped at that
 *     end, and a refresh at or after it revokes the family, so refreshing within
 *     `refreshTtlSeconds` cannot keep a family alive for ever.
 *   - A refresh naming a scope the grant does not hold is refused, but only
 *     after every check above passed: the answer (`invalid_scope` at the token
 *     endpoint) is then given only to the holder of a live, correctly bound
 *     token, and tells them nothing a successful refresh would not.
 *   - The grant's scopes are narrowed to the resource's configured scopes
 *     before anything is minted (a scope removed from the config is dropped
 *     from the successor, and never comes back without a new consent). A grant
 *     left with no scope revokes the family.
 *   - The access token is minted BEFORE the store is written: the caller's
 *     `issue` runs after every check and before the rotation (or the insert),
 *     so a mint that fails leaves the presented refresh token usable. A token
 *     minted for a rotation that then loses its race is never handed out.
 *
 * Every refusal has a reason for the audit sink; the token endpoint answers
 * each one with the same `invalid_grant`.
 */
import type { GrantInfo } from "./config.ts";
import type { Context } from "./context.ts";
import { randomToken, sha256Hex } from "./encoding.ts";
import type { GrantContext, GrantRecord, NewGrant } from "./stores.ts";

export interface IssuedGrant<T> {
  /** The only time the plaintext exists. */
  refreshToken: string;
  info: GrantInfo;
  /** What `issue` returned for this grant (the access token). */
  issued: T;
}

/** Mints what goes out with the grant. Throwing aborts before the store is written. */
export type Issue<T> = (info: GrantInfo) => Promise<T>;

export type RotateFailure =
  | "unknown"
  | "reused"
  | "reused_concurrently"
  | "revoked"
  | "expired"
  | "client_mismatch"
  | "inactive"
  | "no_scope"
  | "family_expired"
  | "scope_not_granted";

export type RotateResult<T> = { ok: true; grant: IssuedGrant<T> } | { ok: false; reason: RotateFailure };

/** The scopes of `scopes` the resource still defines, in their original order. */
export function liveScopes(ctx: Context, scopes: readonly string[]): string[] {
  return scopes.filter((scope) => ctx.config.scopes.includes(scope));
}

export function infoOf(row: Pick<GrantRecord, "subject" | "clientId" | "scopes" | "context" | "familyId" | "authorizedAt">): GrantInfo {
  return {
    subject: row.subject,
    clientId: row.clientId,
    scopes: [...row.scopes],
    context: { ...row.context },
    familyId: row.familyId,
    authorizedAt: new Date(row.authorizedAt),
  };
}

/** Ask the host's isGrantActive. A hook that throws is reported and counts as inactive. */
export async function grantIsActive(ctx: Context, info: GrantInfo): Promise<boolean> {
  if (!ctx.hooks.isGrantActive) return true;
  try {
    return (await ctx.hooks.isGrantActive(info)) === true;
  } catch (err) {
    ctx.report("isGrantActive", err);
    return false;
  }
}

function freshToken(ctx: Context): { handed: string; tokenHash: string } {
  const bare = randomToken(32);
  const handed = ctx.hooks.tokenWrapper ? ctx.hooks.tokenWrapper.wrap("refresh_token", bare) : bare;
  return { handed, tokenHash: sha256Hex(bare) };
}

/** When the family that began at `familyCreatedAt` ends, in milliseconds since the epoch. */
function familyEnd(ctx: Context, familyCreatedAt: Date): number {
  return familyCreatedAt.getTime() + ctx.config.maxFamilyLifetimeSeconds * 1000;
}

function newRow(
  ctx: Context,
  base: {
    familyId: string;
    subject: string;
    clientId: string;
    scopes: readonly string[];
    context: GrantContext;
    authorizedAt: Date;
    familyCreatedAt: Date;
  },
  tokenHash: string,
  now: Date,
): NewGrant {
  // Sliding, but never past the family's end.
  const expiresAt = Math.min(now.getTime() + ctx.config.refreshTtlSeconds * 1000, familyEnd(ctx, base.familyCreatedAt));
  return {
    id: crypto.randomUUID(),
    familyId: base.familyId,
    tokenHash,
    subject: base.subject,
    clientId: base.clientId,
    scopes: [...base.scopes],
    context: { ...base.context },
    authorizedAt: new Date(base.authorizedAt),
    familyCreatedAt: new Date(base.familyCreatedAt),
    createdAt: now,
    expiresAt: new Date(expiresAt),
  };
}

/**
 * Start a family, after a code was spent. `params.familyId` is the id the
 * code's tombstone already names, `params.scopes` must already be live
 * (`liveScopes`) and non-empty, and `params.authorizedAt` is when the person
 * approved (carried in the code), not now. The family begins now. `issue`
 * runs before the insert, so a mint that fails leaves no grant behind.
 */
export async function createGrant<T>(
  ctx: Context,
  params: { familyId: string; subject: string; clientId: string; scopes: readonly string[]; context: GrantContext; authorizedAt: Date },
  issue: Issue<T>,
): Promise<IssuedGrant<T>> {
  const now = new Date(ctx.config.now());
  const { handed, tokenHash } = freshToken(ctx);
  const row = newRow(ctx, { ...params, familyCreatedAt: now }, tokenHash, now);
  const info = infoOf(row);
  const issued = await issue(info);
  await ctx.hooks.grantStore.insert(row);
  await ctx.audit({ type: "grant.created", subject: row.subject, clientId: row.clientId, familyId: row.familyId, scopes: row.scopes });
  return { refreshToken: handed, info, issued };
}

/**
 * Exchange a refresh token for its successor, or refuse. `requested` is the
 * resource scopes the request named (null when it named none). `issue` runs
 * after every check and before the rotation is written: if it throws, nothing
 * is spent and the presented token still works.
 */
export async function rotateGrant<T>(
  ctx: Context,
  presented: string,
  clientId: string,
  requested: readonly string[] | null,
  issue: Issue<T>,
): Promise<RotateResult<T>> {
  const store = ctx.hooks.grantStore;
  const bare = ctx.hooks.tokenWrapper ? ctx.hooks.tokenWrapper.unwrap("refresh_token", presented) : presented;
  if (bare === null) return { ok: false, reason: "unknown" };
  const row = await store.findByTokenHash(sha256Hex(bare));
  if (!row) return { ok: false, reason: "unknown" };
  const now = new Date(ctx.config.now());

  const kill = async (
    reason: "reused" | "reused_concurrently" | "client_mismatch" | "inactive" | "no_scope" | "family_expired",
  ): Promise<{ ok: false; reason: RotateFailure }> => {
    await store.revokeFamily(row.familyId, now);
    await ctx.audit({
      type: "grant.revoked",
      subject: row.subject,
      clientId: row.clientId,
      familyId: row.familyId,
      reason: reason === "reused" || reason === "reused_concurrently" ? "reuse" : reason,
    });
    return { ok: false, reason };
  };
  const reuse = (reason: "reused" | "reused_concurrently") =>
    ctx.config.refreshTokenReuse === "revoke-family" ? kill(reason) : Promise.resolve({ ok: false as const, reason });

  if (row.rotatedAt) return reuse("reused");
  if (row.revokedAt) return { ok: false, reason: "revoked" };
  // Before the row's own expiry: a family past its end is revoked, not left to lapse.
  if (now.getTime() >= familyEnd(ctx, row.familyCreatedAt)) return kill("family_expired");
  if (row.expiresAt.getTime() <= now.getTime()) return { ok: false, reason: "expired" };
  if (row.clientId !== clientId) return kill("client_mismatch");
  if (!(await grantIsActive(ctx, infoOf(row)))) return kill("inactive");
  // A grant whose every scope was removed from the config can never mint again.
  const scopes = liveScopes(ctx, row.scopes);
  if (scopes.length === 0) return kill("no_scope");
  // RFC 6749 section 6: never more than the grant holds. Fewer is accepted and not narrowed (SPEC.md).
  if (requested?.some((scope) => !scopes.includes(scope))) return { ok: false, reason: "scope_not_granted" };

  const { handed, tokenHash } = freshToken(ctx);
  const successor = newRow(ctx, { ...row, scopes }, tokenHash, now);
  const info = infoOf(successor);
  // Before the rotation: a mint that throws spends nothing.
  const issued = await issue(info);
  const outcome = await store.rotate(row.id, now, successor);
  if (outcome === "taken") return reuse("reused_concurrently");
  if (outcome === "revoked") {
    // Revoked between the read and the claim: stamp whatever of the family is still live.
    await store.revokeFamily(row.familyId, now);
    return { ok: false, reason: "revoked" };
  }
  await ctx.audit({ type: "grant.refreshed", subject: row.subject, clientId: row.clientId, familyId: row.familyId });
  return { ok: true, grant: { refreshToken: handed, info, issued } };
}
