/**
 * The storage contracts the host implements. Two in-memory implementations
 * ship in memory-stores.ts; `mcp-frontdesk/testing` exports the contract suite
 * any implementation must pass.
 *
 * Stores only ever see SHA-256 hashes of codes and refresh tokens, never the
 * values handed to clients.
 */

/** Host data carried from approval into the grant and its tokens (a tenant id, for example). */
export type GrantContext = Readonly<Record<string, string>>;

/** What a one-time authorization code is bound to. */
export interface CodeRecord {
  subject: string;
  clientId: string;
  redirectUri: string;
  /** base64url SHA-256 of the client's code_verifier (S256). */
  codeChallenge: string;
  scopes: readonly string[];
  context: GrantContext;
  /** Milliseconds since the epoch. Checked by the token endpoint as well as by the store's TTL. */
  expiresAt: number;
}

export interface CodeStore {
  /**
   * Store `record` under `codeHash` for `ttlSeconds`. Throw (or reject) when
   * the write did not happen: a code that was not stored is never handed out.
   */
  put(codeHash: string, record: CodeRecord, ttlSeconds: number): Promise<void>;
  /**
   * Remove and return the record. MUST be atomic: of any number of concurrent
   * calls for one hash, at most one gets the record. Null when there is none.
   * Throwing is treated as a refusal, never as a licence to continue.
   */
  take(codeHash: string): Promise<CodeRecord | null>;
}

/** One stored refresh token. Every rotation adds a row to the same family. */
export interface GrantRecord {
  id: string;
  familyId: string;
  tokenHash: string;
  subject: string;
  clientId: string;
  scopes: readonly string[];
  context: GrantContext;
  /** When the person approved: the family's first row's creation time. */
  authorizedAt: Date;
  createdAt: Date;
  expiresAt: Date;
  rotatedAt: Date | null;
  revokedAt: Date | null;
}

/** A row to insert. Never rotated or revoked yet. */
export type NewGrant = Omit<GrantRecord, "rotatedAt" | "revokedAt">;

export type RotateOutcome = "rotated" | "taken" | "revoked";

/** One live connection, as a settings page lists it. */
export interface GrantSummary {
  familyId: string;
  clientId: string;
  scopes: readonly string[];
  context: GrantContext;
  authorizedAt: Date;
  /** When the current refresh token was minted (equal to authorizedAt before the first refresh). */
  lastRefreshedAt: Date;
  expiresAt: Date;
}

export interface GrantStore {
  insert(grant: NewGrant): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<GrantRecord | null>;
  /**
   * ATOMIC: stamp `rotatedAt = now` on row `id` only if it is neither rotated
   * nor revoked and no row of its family is revoked, and insert `successor`, as
   * one unit. `"taken"` when the row was already rotated (a concurrent refresh
   * won), `"revoked"` when the row or its family is revoked. In both cases
   * nothing is inserted. A store may prune rows of the family whose own
   * expiresAt is before `now`; it must keep every other rotated row, because a
   * rotated row presented again is how reuse is detected.
   */
  rotate(id: string, now: Date, successor: NewGrant): Promise<RotateOutcome>;
  /**
   * Revoke every unrevoked row of the family, including a successor inserted
   * by a rotation that raced this call. Answers how many rows it revoked.
   */
  revokeFamily(familyId: string, now: Date): Promise<number>;
  /** The subject's live families (an unrevoked, unrotated, unexpired head), newest authorization first. */
  listByUser(subject: string, now: Date): Promise<GrantSummary[]>;
  /** revokeFamily, but only when the family belongs to `subject`. 0 otherwise. */
  revokeFamilyForUser(subject: string, familyId: string, now: Date): Promise<number>;
}
