// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { MemoryCodeStore, MemoryGrantStore } from "../src/memory-stores.ts";
import type { CodeRecord, CodeStore, GrantRecord, GrantStore, NewGrant, SpentCode } from "../src/stores.ts";
import { codeStoreContract, grantStoreContract } from "../src/testing.ts";
import { clock } from "./helpers.ts";

describe("the store contract suite, against the in-memory stores", () => {
  // One clock for every code store in the suite, moved by the suite's `sleep`.
  const time = clock();
  for (const c of codeStoreContract(() => new MemoryCodeStore({ now: time.now }), { sleep: async (ms) => time.advance(ms) })) it(c.name, c.run);
  for (const c of grantStoreContract(() => new MemoryGrantStore())) it(c.name, c.run);
});

describe("the contract suite's tombstone lifetime case", () => {
  it("sleeps on a real timer by default, for the whole 900 ms", async (t) => {
    // Date too: the store's default clock then moves with the timer, not with the machine.
    t.mock.timers.enable({ apis: ["setTimeout", "Date"] });
    const lifetime = codeStoreContract(() => new MemoryCodeStore()).find((c) => c.name.includes("lasts at least"))!;
    let finished = false;
    const run = lifetime.run().then(() => {
      finished = true;
    });
    // The store is in memory, so one turn of the event loop brings the case to its sleep.
    await new Promise((resolve) => setImmediate(resolve));
    t.mock.timers.tick(899);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(finished, false, "the default sleep ended before 900 ms");
    t.mock.timers.tick(1);
    await run;
    assert.equal(finished, true);
  });
});

describe("stores.ts", () => {
  it("holds the storage contracts as types alone: nothing of it exists at run time", async () => {
    assert.deepEqual(Object.keys(await import("../src/stores.ts")), []);
  });
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
    async markReplayed() {
      return null;
    }
    async wasReplayed() {
      return false;
    }
  }

  /** Atomic takes, but the tombstone is written by every take, so a replay's take overwrites the family. */
  class OverwritingCodeStore extends MemoryCodeStore {
    readonly #families = new Map<string, string>();
    override async take(hash: string, spent: SpentCode) {
      this.#families.set(hash, spent.familyId);
      return super.take(hash, spent);
    }
    override async markReplayed(hash: string) {
      return (await super.markReplayed(hash)) === null ? null : (this.#families.get(hash) ?? null);
    }
  }

  /** Atomic takes, and no tombstone at all. */
  class ForgetfulCodeStore extends MemoryCodeStore {
    override async markReplayed() {
      return null;
    }
  }

  /** A rotate that checks, yields, then writes. */
  class RacyGrantStore extends MemoryGrantStore implements GrantStore {
    override async rotate(id: string, _now: Date, successor: NewGrant) {
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

  it("a take that leaves no tombstone fails the tombstone case", async () => {
    const tombstone = codeStoreContract(() => new ForgetfulCodeStore()).find((c) => c.name.includes("leaves a tombstone"))!;
    await assert.rejects(tombstone.run());
  });

  it("a store that forgets a tombstone before its lifetime fails the lifetime case", async () => {
    const time = clock();
    /** Keeps each tombstone for half the lifetime it was given. */
    class ShortLivedCodeStore extends MemoryCodeStore {
      override async take(hash: string, spent: SpentCode) {
        return super.take(hash, { ...spent, ttlSeconds: spent.ttlSeconds / 2 });
      }
    }
    const lifetime = codeStoreContract(() => new ShortLivedCodeStore({ now: time.now }), { sleep: async (ms) => time.advance(ms) }).find((c) =>
      c.name.includes("lasts at least"),
    )!;
    await assert.rejects(lifetime.run(), /forgot the spent code before its lifetime/);
  });

  it("a take that replaces the tombstone of a spent code fails the replay case", async () => {
    const overwrite = codeStoreContract(() => new OverwritingCodeStore()).find((c) => c.name.includes("never replaces one"))!;
    await assert.rejects(overwrite.run(), /did not overwrite the tombstone/);
  });

  it("a store that does not keep familyCreatedAt fails the family-lifetime case", async () => {
    class DroppingStore extends MemoryGrantStore {
      override async findByTokenHash(tokenHash: string) {
        const row = await super.findByTokenHash(tokenHash);
        return row && { ...row, familyCreatedAt: row.createdAt };
      }
    }
    const kept = grantStoreContract(() => new DroppingStore()).find((c) => c.name.includes("familyCreatedAt"))!;
    await assert.rejects(kept.run());
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
  const record: CodeRecord = { subject: "s", clientId: "c", redirectUri: "r", codeChallenge: "x", scopes: ["a"], context: {}, authorizedAt: 0, expiresAt: 0 };
  const spent = (familyId: string, ttlSeconds = 600): SpentCode => ({ familyId, ttlSeconds });

  it("expires codes on its own clock and sweeps them on the next put", async () => {
    const time = clock();
    const store = new MemoryCodeStore({ now: time.now });
    await store.put("a", record, 60);
    await store.put("b", record, 120);
    time.advance(60_000);
    assert.equal(await store.take("a", spent("f")), null);
    await store.put("c", record, 60); // sweeps nothing more: b is still live
    assert.ok(await store.take("b", spent("f")));
    await store.put("d", record, 1);
    time.advance(1_000);
    await store.put("e", record, 60); // sweeps d
    assert.equal(await store.take("d", spent("f")), null);
  });

  it("an expired code it refuses leaves no tombstone", async () => {
    const time = clock();
    const store = new MemoryCodeStore({ now: time.now });
    await store.put("a", record, 60);
    time.advance(60_000);
    assert.equal(await store.take("a", spent("f")), null);
    assert.equal(await store.markReplayed("a"), null);
  });

  it("forgets a tombstone after its lifetime, on its own clock, and sweeps it on the next put", async () => {
    const time = clock();
    const store = new MemoryCodeStore({ now: time.now });
    await store.put("a", record, 60);
    await store.put("b", record, 60);
    assert.ok(await store.take("a", spent("fa", 120)));
    assert.ok(await store.take("b", spent("fb", 600)));
    time.advance(119_999);
    assert.equal(await store.wasReplayed("a"), false);
    assert.equal(await store.markReplayed("a"), "fa", "still remembered just before its lifetime ends");
    time.advance(1);
    assert.equal(await store.wasReplayed("a"), false, "forgotten, replay flag and all");
    assert.equal(await store.markReplayed("a"), null);
    await store.put("c", record, 60); // sweeps nothing more: b's tombstone is still live
    assert.equal(await store.markReplayed("b"), "fb");
    time.advance(600_000);
    await store.put("d", record, 60); // sweeps b's tombstone
    assert.equal(await store.markReplayed("b"), null);
  });

  it("uses the wall clock by default", async () => {
    const store = new MemoryCodeStore();
    await store.put("a", record, 60);
    assert.ok(await store.take("a", spent("f")));
    assert.equal(await store.markReplayed("a"), "f");
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
    familyCreatedAt: new Date(0),
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
