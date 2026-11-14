import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { MemoryCodeStore, MemoryGrantStore } from "../src/memory-stores.ts";
import type { CodeRecord, CodeStore, GrantRecord, GrantStore, NewGrant } from "../src/stores.ts";
import { codeStoreContract, grantStoreContract } from "../src/testing.ts";
import { clock } from "./helpers.ts";

describe("the store contract suite, against the in-memory stores", () => {
  for (const c of codeStoreContract(() => new MemoryCodeStore())) it(c.name, c.run);
  for (const c of grantStoreContract(() => new MemoryGrantStore())) it(c.name, c.run);
});

describe("the contract suite catches broken stores", () => {
  /** A take that reads, yields, then deletes: two concurrent takes both win. */
  class RacyCodeStore implements CodeStore {
    readonly #map = new Map<string, CodeRecord>();
    async put(hash: string, record: CodeRecord) {
      this.#map.set(hash, record);
    }
    async take(hash: string) {
      const record = this.#map.get(hash) ?? null;
      await new Promise((resolve) => setImmediate(resolve));
      this.#map.delete(hash);
      return record;
    }
  }

  /** A rotate that checks, yields, then writes. */
  class RacyGrantStore extends MemoryGrantStore implements GrantStore {
    override async rotate(id: string, now: Date, successor: NewGrant) {
      await new Promise((resolve) => setImmediate(resolve));
      const rows = await this.findAll(id);
      if (!rows) return "revoked" as const;
      await this.insert(successor);
      return "rotated" as const;
    }
    async findAll(_id: string) {
      return true;
    }
  }

  /** A revokeFamily that reads the family, yields, then stamps only the rows it read. */
  class SnapshotRevokeStore implements GrantStore {
    readonly #rows = new Map<string, GrantRecord>();
    async insert(grant: NewGrant) {
      this.#rows.set(grant.id, { ...grant, rotatedAt: null, revokedAt: null });
    }
    async findByTokenHash(tokenHash: string) {
      for (const row of this.#rows.values()) if (row.tokenHash === tokenHash) return { ...row };
      return null;
    }
    async rotate(id: string, now: Date, successor: NewGrant) {
      await new Promise((resolve) => setImmediate(resolve));
      const row = this.#rows.get(id)!;
      if ([...this.#rows.values()].some((r) => r.familyId === row.familyId && r.revokedAt)) return "revoked" as const;
      row.rotatedAt = now;
      this.#rows.set(successor.id, { ...successor, rotatedAt: null, revokedAt: null });
      return "rotated" as const;
    }
    async revokeFamily(familyId: string, now: Date) {
      const snapshot = [...this.#rows.values()].filter((r) => r.familyId === familyId && !r.revokedAt);
      await new Promise((resolve) => setImmediate(resolve));
      for (const row of snapshot) row.revokedAt = now;
      return snapshot.length;
    }
    async listByUser() {
      return [];
    }
    async revokeFamilyForUser() {
      return 0;
    }
  }

  it("a non-atomic take fails the concurrency case", async () => {
    const race = codeStoreContract(() => new RacyCodeStore()).find((c) => c.name.includes("concurrent"))!;
    await assert.rejects(race.run());
  });

  it("a non-atomic rotate fails the concurrency case", async () => {
    const race = grantStoreContract(() => new RacyGrantStore()).find((c) => c.name.includes("concurrent"))!;
    await assert.rejects(race.run());
  });

  it("a revokeFamily that misses a successor inserted by a racing rotation fails the race case", async () => {
    const race = grantStoreContract(() => new SnapshotRevokeStore()).find((c) => c.name.includes("racing a rotation"))!;
    await assert.rejects(race.run(), /a row of a revoked family stayed live/);
  });
});

describe("MemoryCodeStore", () => {
  it("expires codes on its own clock and sweeps them on the next put", async () => {
    const time = clock();
    const store = new MemoryCodeStore({ now: time.now });
    const record: CodeRecord = { subject: "s", clientId: "c", redirectUri: "r", codeChallenge: "x", scopes: ["a"], context: {}, authorizedAt: 0, expiresAt: 0 };
    await store.put("a", record, 60);
    await store.put("b", record, 120);
    time.advance(60_000);
    assert.equal(await store.take("a"), null);
    await store.put("c", record, 60); // sweeps nothing more: b is still live
    assert.ok(await store.take("b"));
    await store.put("d", record, 1);
    time.advance(1_000);
    await store.put("e", record, 60); // sweeps d
    assert.equal(await store.take("d"), null);
  });

  it("uses the wall clock by default", async () => {
    const store = new MemoryCodeStore();
    await store.put("a", { subject: "s", clientId: "c", redirectUri: "r", codeChallenge: "x", scopes: ["a"], context: {}, authorizedAt: 0, expiresAt: 0 }, 60);
    assert.ok(await store.take("a"));
  });
});

describe("MemoryGrantStore", () => {
  const row = (over: Partial<NewGrant>): NewGrant => ({
    id: "r1",
    familyId: "f1",
    tokenHash: "h1",
    subject: "s",
    clientId: "c",
    scopes: ["a"],
    context: {},
    authorizedAt: new Date(0),
    createdAt: new Date(0),
    expiresAt: new Date(1_000),
    ...over,
  });

  it("prunes the family's expired rows on rotation, keeping live rotated ones", async () => {
    const store = new MemoryGrantStore();
    await store.insert(row({ id: "old", tokenHash: "old", expiresAt: new Date(500) }));
    await store.insert(row({ id: "head", tokenHash: "head", expiresAt: new Date(5_000) }));
    await store.insert(row({ id: "other", familyId: "f2", tokenHash: "other", expiresAt: new Date(500) }));
    assert.equal(await store.rotate("head", new Date(1_000), row({ id: "next", tokenHash: "next", expiresAt: new Date(9_000) })), "rotated");
    assert.equal(await store.findByTokenHash("old"), null);
    assert.ok((await store.findByTokenHash("head"))?.rotatedAt);
    assert.ok(await store.findByTokenHash("other"), "another family is untouched");
  });

  it("answers revoked for an id it does not hold", async () => {
    assert.equal(await new MemoryGrantStore().rotate("nope", new Date(), row({})), "revoked");
  });

  it("returns copies, so a caller cannot change what is stored", async () => {
    const store = new MemoryGrantStore();
    await store.insert(row({}));
    const found = (await store.findByTokenHash("h1"))!;
    (found.scopes as string[]).push("b");
    assert.deepEqual((await store.findByTokenHash("h1"))?.scopes, ["a"]);
  });
});
