/**
 * The package's entry points. Each subpath in package.json "exports" is built
 * from one module in src/, and each exports exactly the values below at run
 * time (its types are erased). Adding or dropping one changes the public API,
 * so it is done here on purpose, never by accident.
 */
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { claudeClients, DEFAULT_MAX_FAMILY_LIFETIME_SECONDS, DEFAULT_TTL, FrontdeskConfigError, MAX_FAMILY_LIFETIME_SECONDS } from "../src/config.ts";
import * as experimental from "../src/experimental.ts";
import { createFrontdesk } from "../src/frontdesk.ts";
import { bearerTokenFrom } from "../src/gate.ts";
import * as entry from "../src/index.ts";
import { generateSigningJwk, KeyConfigError, keyProviderFromJwk, publicJwk } from "../src/keys.ts";
import { MemoryCodeStore, MemoryGrantStore } from "../src/memory-stores.ts";
import * as testing from "../src/testing.ts";

type ExportTarget = string | { types: string; default: string };
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, ExportTarget> };

describe("the package's entry points", () => {
  it("package.json exports three entries, each built from its own module in src/", () => {
    const entries = Object.entries(pkg.exports)
      .filter(([subpath]) => subpath !== "./package.json")
      .map(([subpath, target]) => [subpath, typeof target === "string" ? target : target.default]);
    assert.deepEqual(entries, [
      [".", "./dist/index.js"],
      ["./experimental", "./dist/experimental.js"],
      ["./testing", "./dist/testing.js"],
    ]);
  });

  it("mcp-frontdesk exports the implementations themselves, and nothing else", () => {
    const expected = {
      claudeClients,
      createFrontdesk,
      DEFAULT_MAX_FAMILY_LIFETIME_SECONDS,
      DEFAULT_TTL,
      FrontdeskConfigError,
      MAX_FAMILY_LIFETIME_SECONDS,
      bearerTokenFrom,
      generateSigningJwk,
      KeyConfigError,
      keyProviderFromJwk,
      publicJwk,
      MemoryCodeStore,
      MemoryGrantStore,
    };
    assert.deepEqual(Object.keys(entry).sort(), Object.keys(expected).sort());
    for (const [name, value] of Object.entries(expected)) assert.equal(entry[name as keyof typeof entry], value, name);
  });

  it("mcp-frontdesk/experimental and mcp-frontdesk/testing export their functions alone", () => {
    assert.deepEqual(Object.keys(experimental), ["createFence"]);
    assert.deepEqual(Object.keys(testing).sort(), ["codeStoreContract", "grantStoreContract"]);
  });
});
