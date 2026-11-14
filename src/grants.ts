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
 *   - A refresh token is bound to its client: presented by another client_id,
 *     the family is revoked whatever the reuse policy.
 *   - `isGrantActive` is asked before every rotation; false revokes the family.
 *
 * Every refusal has a reason for the audit sink; the token endpoint answers
 * each one with the same `invalid_grant`.
 */
import type { GrantInfo } from "./config.ts";
import type { Context } from "./context.ts";
import { randomToken, sha256Hex } from "./encoding.ts";
import type { GrantContext, GrantRecord, NewGrant } from "./stores.ts";

export interface IssuedGrant {
  /** The only time the plaintext exists. */
  refreshToken: string;
  info: GrantInfo;
}

export type RotateFailure =
  | "unknown"
  | "reused"
  | "reused_concurrently"
  | "revoked"
  | "expired"
  | "client_mismatch"
  | "inactive";

export type RotateResult = { ok: true; grant: IssuedGrant } | { ok: false; reason: RotateFailure };

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

function newRow(
  ctx: Context,
  base: { familyId: string; subject: string; clientId: string; scopes: readonly string[]; context: GrantContext; authorizedAt: Date },
  tokenHash: string,
  now: Date,
): NewGrant {
  return {
    id: crypto.randomUUID(),
    familyId: base.familyId,
    tokenHash,
    subject: base.subject,
    clientId: base.clientId,
    scopes: [...base.scopes],
    context: { ...base.context },
    authorizedAt: new Date(base.authorizedAt),
    createdAt: now,
    expiresAt: new Date(now.getTime() + ctx.config.refreshTtlSeconds * 1000),
  };
}

/** Start a family, after a code was spent. */
export async function createGrant(
  ctx: Context,
  params: { subject: string; clientId: string; scopes: readonly string[]; context: GrantContext },
): Promise<IssuedGrant> {
  const now = new Date(ctx.config.now());
  const { handed, tokenHash } = freshToken(ctx);
  const row = newRow(ctx, { ...params, familyId: crypto.randomUUID(), authorizedAt: now }, tokenHash, now);
  await ctx.hooks.grantStore.insert(row);
  await ctx.audit({ type: "grant.created", subject: row.subject, clientId: row.clientId, familyId: row.familyId, scopes: row.scopes });
  return { refreshToken: handed, info: infoOf(row) };
}

/** Exchange a refresh token for its successor, or refuse. */
export async function rotateGrant(ctx: Context, presented: string, clientId: string): Promise<RotateResult> {
  const store = ctx.hooks.grantStore;
  const bare = ctx.hooks.tokenWrapper ? ctx.hooks.tokenWrapper.unwrap("refresh_token", presented) : presented;
  if (bare === null) return { ok: false, reason: "unknown" };
  const row = await store.findByTokenHash(sha256Hex(bare));
  if (!row) return { ok: false, reason: "unknown" };
  const now = new Date(ctx.config.now());

  const kill = async (
    reason: "reused" | "reused_concurrently" | "client_mismatch" | "inactive",
  ): Promise<{ ok: false; reason: RotateFailure }> => {
    await store.revokeFamily(row.familyId, now);
    await ctx.audit({
      type: "grant.revoked",
      subject: row.subject,
      clientId: row.clientId,
      familyId: row.familyId,
      reason: reason === "client_mismatch" || reason === "inactive" ? reason : "reuse",
    });
    return { ok: false, reason };
  };
  const reuse = (reason: "reused" | "reused_concurrently") =>
    ctx.config.refreshTokenReuse === "revoke-family" ? kill(reason) : Promise.resolve({ ok: false as const, reason });

  if (row.rotatedAt) return reuse("reused");
  if (row.revokedAt) return { ok: false, reason: "revoked" };
  if (row.expiresAt.getTime() <= now.getTime()) return { ok: false, reason: "expired" };
  if (row.clientId !== clientId) return kill("client_mismatch");
  if (!(await grantIsActive(ctx, infoOf(row)))) return kill("inactive");

  const { handed, tokenHash } = freshToken(ctx);
  const successor = newRow(ctx, row, tokenHash, now);
  const outcome = await store.rotate(row.id, now, successor);
  if (outcome === "taken") return reuse("reused_concurrently");
  if (outcome === "revoked") {
    // Revoked between the read and the claim: stamp whatever of the family is still live.
    await store.revokeFamily(row.familyId, now);
    return { ok: false, reason: "revoked" };
  }
  await ctx.audit({ type: "grant.refreshed", subject: row.subject, clientId: row.clientId, familyId: row.familyId });
  return { ok: true, grant: { refreshToken: handed, info: infoOf(successor) } };
}
