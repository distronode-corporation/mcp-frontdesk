/**
 * mcp-frontdesk/testing: the contract every CodeStore and GrantStore must meet.
 *
 * Runner-agnostic: each suite is a list of `{ name, run }` cases, and `run`
 * throws (node:assert) on a failure. With node:test, vitest or jest:
 *
 *     for (const c of grantStoreContract(() => new MyGrantStore())) test(c.name, c.run);
 *
 * `makeStore` is called once per case, and must return an empty store (a fresh
 * table, or a fresh key prefix). The atomicity cases fire concurrent calls,
 * so a store whose take or rotate is a read followed by a separate write fails
 * them, as it should.
 */
import { deepStrictEqual, ok, strictEqual } from "node:assert/strict";

import type { CodeRecord, CodeStore, GrantStore, NewGrant } from "./stores.ts";

export interface ContractCase {
  name: string;
  run: () => Promise<void>;
}

type Factory<T> = () => T | Promise<T>;

const CODE: CodeRecord = {
  subject: "user-1",
  clientId: "https://client.example.com/metadata.json",
  redirectUri: "https://client.example.com/callback",
  codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  scopes: ["notes:read"],
  context: { tenant: "t-1" },
  authorizedAt: Date.UTC(2029, 11, 31, 23, 59),
  expiresAt: Date.UTC(2030, 0, 1),
};

let counter = 0;
const unique = (prefix: string) => `${prefix}-${Date.now().toString(36)}-${(counter += 1)}`;

/** What the token endpoint passes to `take`: the family the redemption will start, and how long to remember it. */
const spent = (familyId = unique("fam")) => ({ familyId, ttlSeconds: 600 });

export function codeStoreContract(makeStore: Factory<CodeStore>): ContractCase[] {
  return [
    {
      name: "code store: take returns what put stored, once",
      async run() {
        const store = await makeStore();
        const hash = unique("code");
        await store.put(hash, CODE, 60);
        deepStrictEqual(await store.take(hash, spent()), CODE);
        strictEqual(await store.take(hash, spent()), null);
      },
    },
    {
      name: "code store: take of an unknown hash is null",
      async run() {
        const store = await makeStore();
        strictEqual(await store.take(unique("never"), spent()), null);
      },
    },
    {
      name: "code store: codes are independent",
      async run() {
        const store = await makeStore();
        const [a, b] = [unique("a"), unique("b")];
        await store.put(a, CODE, 60);
        await store.put(b, { ...CODE, subject: "user-2" }, 60);
        strictEqual((await store.take(b, spent()))?.subject, "user-2");
        strictEqual((await store.take(a, spent()))?.subject, "user-1");
      },
    },
    {
      name: "code store: of concurrent takes, exactly one gets the record",
      async run() {
        const store = await makeStore();
        const hash = unique("race");
        await store.put(hash, CODE, 60);
        const results = await Promise.all(Array.from({ length: 8 }, () => store.take(hash, spent())));
        strictEqual(results.filter((r) => r !== null).length, 1);
      },
    },
    {
      name: "code store: a take that returns the record leaves a tombstone naming its family",
      async run() {
        const store = await makeStore();
        const hash = unique("code");
        const family = unique("fam");
        await store.put(hash, CODE, 60);
        deepStrictEqual(await store.take(hash, spent(family)), CODE);
        strictEqual(await store.wasReplayed(hash), false, "nothing replayed it yet");
        strictEqual(await store.markReplayed(hash), family);
        strictEqual(await store.wasReplayed(hash), true);
        strictEqual(await store.markReplayed(hash), family, "a second replay names the same family");
      },
    },
    {
      name: "code store: a take with nothing to take leaves no tombstone, and never replaces one",
      async run() {
        const store = await makeStore();
        const never = unique("never");
        strictEqual(await store.take(never, spent()), null);
        strictEqual(await store.markReplayed(never), null);
        strictEqual(await store.wasReplayed(never), false);

        const hash = unique("code");
        const family = unique("fam");
        await store.put(hash, CODE, 60);
        await store.take(hash, spent(family));
        strictEqual(await store.take(hash, spent(unique("other"))), null);
        strictEqual(await store.markReplayed(hash), family, "the replay's take did not overwrite the tombstone");
      },
    },
    {
      name: "code store: a code that was put but never taken has no tombstone",
      async run() {
        const store = await makeStore();
        const hash = unique("code");
        await store.put(hash, CODE, 60);
        strictEqual(await store.markReplayed(hash), null);
        strictEqual(await store.wasReplayed(hash), false);
        deepStrictEqual(await store.take(hash, spent()), CODE, "markReplayed did not spend the code");
      },
    },
    {
      name: "code store: of concurrent takes, the tombstone names the winner's family",
      async run() {
        const store = await makeStore();
        const hash = unique("race");
        await store.put(hash, CODE, 60);
        const families = Array.from({ length: 8 }, () => unique("fam"));
        const results = await Promise.all(families.map((family) => store.take(hash, spent(family))));
        const winner = results.findIndex((r) => r !== null);
        ok(winner !== -1, "one take got the record");
        strictEqual(await store.markReplayed(hash), families[winner]);
      },
    },
  ];
}

function grantRow(familyId: string, overrides: Partial<NewGrant> = {}): NewGrant {
  const now = new Date(Date.UTC(2030, 0, 1));
  return {
    id: unique("row"),
    familyId,
    tokenHash: unique("hash"),
    subject: "user-1",
    clientId: "https://client.example.com/metadata.json",
    scopes: ["notes:read"],
    context: { tenant: "t-1" },
    authorizedAt: now,
    familyCreatedAt: now,
    createdAt: now,
    expiresAt: new Date(now.getTime() + 86_400_000),
    ...overrides,
  };
}

const T0 = new Date(Date.UTC(2030, 0, 1, 1));

export function grantStoreContract(makeStore: Factory<GrantStore>): ContractCase[] {
  return [
    {
      name: "grant store: a row is found by its hash, intact and live",
      async run() {
        const store = await makeStore();
        const row = grantRow(unique("fam"));
        await store.insert(row);
        deepStrictEqual(await store.findByTokenHash(row.tokenHash), { ...row, rotatedAt: null, revokedAt: null });
        strictEqual(await store.findByTokenHash(unique("nope")), null);
      },
    },
    {
      name: "grant store: familyCreatedAt is kept as written on every row of a family",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const began = new Date(Date.UTC(2029, 5, 1));
        const row = grantRow(family, { familyCreatedAt: began, createdAt: began });
        await store.insert(row);
        const next = grantRow(family, { familyCreatedAt: began, createdAt: T0 });
        strictEqual(await store.rotate(row.id, T0, next), "rotated");
        deepStrictEqual((await store.findByTokenHash(row.tokenHash))?.familyCreatedAt, began);
        deepStrictEqual((await store.findByTokenHash(next.tokenHash))?.familyCreatedAt, began, "not the successor's own createdAt");
      },
    },
    {
      name: "grant store: rotate stamps the row and inserts the successor",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const row = grantRow(family);
        const next = grantRow(family, { createdAt: T0 });
        await store.insert(row);
        strictEqual(await store.rotate(row.id, T0, next), "rotated");
        deepStrictEqual((await store.findByTokenHash(row.tokenHash))?.rotatedAt, T0);
        deepStrictEqual(await store.findByTokenHash(next.tokenHash), { ...next, rotatedAt: null, revokedAt: null });
      },
    },
    {
      name: "grant store: rotating a rotated row is taken, and inserts nothing",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const row = grantRow(family);
        await store.insert(row);
        strictEqual(await store.rotate(row.id, T0, grantRow(family)), "rotated");
        const late = grantRow(family);
        strictEqual(await store.rotate(row.id, T0, late), "taken");
        strictEqual(await store.findByTokenHash(late.tokenHash), null);
      },
    },
    {
      name: "grant store: of concurrent rotations of one row, exactly one wins",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const row = grantRow(family);
        await store.insert(row);
        const successors = Array.from({ length: 8 }, () => grantRow(family));
        const outcomes = await Promise.all(successors.map((s) => store.rotate(row.id, T0, s)));
        strictEqual(outcomes.filter((o) => o === "rotated").length, 1);
        ok(outcomes.every((o) => o === "rotated" || o === "taken"));
        const live = await Promise.all(successors.map((s) => store.findByTokenHash(s.tokenHash)));
        strictEqual(live.filter((r) => r !== null).length, 1);
      },
    },
    {
      name: "grant store: rotating a revoked row, or a row of a revoked family, is revoked",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const row = grantRow(family);
        await store.insert(row);
        strictEqual(await store.revokeFamily(family, T0), 1);
        const next = grantRow(family);
        strictEqual(await store.rotate(row.id, T0, next), "revoked");
        strictEqual(await store.findByTokenHash(next.tokenHash), null);

        const other = unique("fam");
        const a = grantRow(other);
        const b = grantRow(other);
        await store.insert(a);
        await store.insert(b);
        // Revoke a single row by revoking the family, then insert a new unrevoked row into it.
        await store.revokeFamily(other, T0);
        const c = grantRow(other);
        await store.insert(c);
        strictEqual(await store.rotate(c.id, T0, grantRow(other)), "revoked");
      },
    },
    {
      name: "grant store: revokeFamily revokes every live row once, and only that family",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const keep = unique("fam");
        const rows = [grantRow(family), grantRow(family), grantRow(keep)];
        for (const r of rows) await store.insert(r);
        strictEqual(await store.revokeFamily(family, T0), 2);
        strictEqual(await store.revokeFamily(family, T0), 0);
        deepStrictEqual((await store.findByTokenHash(rows[0]!.tokenHash))?.revokedAt, T0);
        strictEqual((await store.findByTokenHash(rows[2]!.tokenHash))?.revokedAt, null);
      },
    },
    {
      name: "grant store: a revocation racing a rotation leaves no live row",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const row = grantRow(family);
        await store.insert(row);
        const next = grantRow(family);
        await Promise.all([store.rotate(row.id, T0, next), store.revokeFamily(family, T0)]);
        // One revokeFamily, no second pass: it must catch a successor the racing rotation inserted.
        for (const r of [row, next]) {
          const found = await store.findByTokenHash(r.tokenHash);
          ok(found === null || found.revokedAt !== null, "a row of a revoked family stayed live");
        }
      },
    },
    {
      name: "grant store: listByUser lists live heads only, newest authorization first",
      async run() {
        const store = await makeStore();
        const subject = unique("user");
        const older = unique("fam");
        const newer = unique("fam");
        const gone = unique("fam");
        const old1 = grantRow(older, { subject, authorizedAt: new Date(Date.UTC(2029, 0, 1)) });
        await store.insert(old1);
        const old2 = grantRow(older, { subject, authorizedAt: old1.authorizedAt, createdAt: T0 });
        strictEqual(await store.rotate(old1.id, T0, old2), "rotated");
        await store.insert(grantRow(newer, { subject }));
        await store.insert(grantRow(gone, { subject }));
        await store.revokeFamily(gone, T0);
        await store.insert(grantRow(unique("fam"), { subject, expiresAt: new Date(T0.getTime() - 1) }));
        await store.insert(grantRow(unique("fam"), { subject: unique("someone-else") }));
        const listed = await store.listByUser(subject, T0);
        deepStrictEqual(
          listed.map((g) => g.familyId),
          [newer, older],
        );
        deepStrictEqual(listed[1], {
          familyId: older,
          clientId: old2.clientId,
          scopes: old2.scopes,
          context: old2.context,
          authorizedAt: old1.authorizedAt,
          lastRefreshedAt: T0,
          expiresAt: old2.expiresAt,
        });
      },
    },
    {
      name: "grant store: revokeFamilyForUser touches only the subject's own family",
      async run() {
        const store = await makeStore();
        const family = unique("fam");
        const row = grantRow(family);
        await store.insert(row);
        strictEqual(await store.revokeFamilyForUser(unique("intruder"), family, T0), 0);
        strictEqual((await store.findByTokenHash(row.tokenHash))?.revokedAt, null);
        strictEqual(await store.revokeFamilyForUser(row.subject, family, T0), 1);
        deepStrictEqual((await store.findByTokenHash(row.tokenHash))?.revokedAt, T0);
      },
    },
  ];
}
