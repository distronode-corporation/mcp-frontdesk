// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

/**
 * In-memory stores: for tests, examples and single-process servers. Everything
 * is lost on restart, and nothing is shared between processes, so a server
 * running more than one instance needs stores of its own (and must run the
 * contract suite in `mcp-frontdesk/testing` against them).
 *
 * Atomicity comes from JavaScript's single thread: each method does its reads
 * and writes without awaiting in between.
 */
import type { CodeRecord, CodeStore, GrantRecord, GrantStore, GrantSummary, NewGrant, RotateOutcome, SpentCode } from "./stores.ts";

export interface MemoryStoreOptions {
  /** Clock in milliseconds. Defaults to `Date.now`. */
  now?: () => number;
}

export class MemoryCodeStore implements CodeStore {
  readonly #codes = new Map<string, { record: CodeRecord; expiresAt: number }>();
  readonly #spent = new Map<string, { familyId: string; replayed: boolean; expiresAt: number }>();
  readonly #now: () => number;

  constructor(options: MemoryStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
  }

  async put(codeHash: string, record: CodeRecord, ttlSeconds: number): Promise<void> {
    this.#sweep();
    this.#codes.set(codeHash, { record: structuredClone(record), expiresAt: this.#now() + ttlSeconds * 1000 });
  }

  async take(codeHash: string, spent: SpentCode): Promise<CodeRecord | null> {
    const entry = this.#codes.get(codeHash);
    this.#codes.delete(codeHash);
    const now = this.#now();
    if (!entry || entry.expiresAt <= now) return null;
    this.#spent.set(codeHash, { familyId: spent.familyId, replayed: false, expiresAt: now + spent.ttlSeconds * 1000 });
    return entry.record;
  }

  async markReplayed(codeHash: string): Promise<string | null> {
    const tombstone = this.#tombstone(codeHash);
    if (!tombstone) return null;
    tombstone.replayed = true;
    return tombstone.familyId;
  }

  async wasReplayed(codeHash: string): Promise<boolean> {
    return this.#tombstone(codeHash)?.replayed === true;
  }

  #tombstone(codeHash: string) {
    const tombstone = this.#spent.get(codeHash);
    if (tombstone && tombstone.expiresAt <= this.#now()) {
      this.#spent.delete(codeHash);
      return undefined;
    }
    return tombstone;
  }

  /** Drop expired codes and tombstones, so an abandoned flow does not stay in memory. */
  #sweep(): void {
    const now = this.#now();
    for (const [hash, entry] of this.#codes) if (entry.expiresAt <= now) this.#codes.delete(hash);
    for (const [hash, entry] of this.#spent) if (entry.expiresAt <= now) this.#spent.delete(hash);
  }
}

export class MemoryGrantStore implements GrantStore {
  readonly #rows = new Map<string, GrantRecord>();

  async insert(grant: NewGrant): Promise<void> {
    this.#add(grant);
  }

  async findByTokenHash(tokenHash: string): Promise<GrantRecord | null> {
    for (const row of this.#rows.values()) if (row.tokenHash === tokenHash) return structuredClone(row);
    return null;
  }

  async rotate(id: string, now: Date, successor: NewGrant): Promise<RotateOutcome> {
    const row = this.#rows.get(id);
    if (!row || row.revokedAt || this.#family(row.familyId).some((r) => r.revokedAt)) return "revoked";
    if (row.rotatedAt) return "taken";
    row.rotatedAt = new Date(now);
    for (const r of this.#family(row.familyId)) if (r.expiresAt < now) this.#rows.delete(r.id);
    this.#add(successor);
    return "rotated";
  }

  async revokeFamily(familyId: string, now: Date): Promise<number> {
    return this.#revoke(this.#family(familyId), now);
  }

  async listByUser(subject: string, now: Date): Promise<GrantSummary[]> {
    const heads = [...this.#rows.values()].filter(
      (r) => r.subject === subject && !r.revokedAt && !r.rotatedAt && r.expiresAt > now,
    );
    return heads
      .map((r) => ({
        familyId: r.familyId,
        clientId: r.clientId,
        scopes: [...r.scopes],
        context: { ...r.context },
        authorizedAt: new Date(r.authorizedAt),
        lastRefreshedAt: new Date(r.createdAt),
        expiresAt: new Date(r.expiresAt),
      }))
      .sort((a, b) => b.authorizedAt.getTime() - a.authorizedAt.getTime());
  }

  async revokeFamilyForUser(subject: string, familyId: string, now: Date): Promise<number> {
    return this.#revoke(
      this.#family(familyId).filter((r) => r.subject === subject),
      now,
    );
  }

  #add(grant: NewGrant): void {
    this.#rows.set(grant.id, { ...structuredClone(grant), rotatedAt: null, revokedAt: null });
  }

  #family(familyId: string): GrantRecord[] {
    return [...this.#rows.values()].filter((r) => r.familyId === familyId);
  }

  #revoke(rows: GrantRecord[], now: Date): number {
    let count = 0;
    for (const row of rows) {
      if (row.revokedAt) continue;
      row.revokedAt = new Date(now);
      count += 1;
    }
    return count;
  }
}
