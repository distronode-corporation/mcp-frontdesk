// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  isInternalHostname,
  isPrivateOrReservedAddress,
  isPrivateOrReservedIpv4,
  isPrivateOrReservedIpv6,
  resolvePublicAddresses,
  systemResolver,
} from "../src/ssrf.ts";

describe("address classification (safety property 1)", () => {
  it("refuses every private, loopback, link-local, shared, reserved and documentation IPv4 range", () => {
    for (const ip of [
      "0.0.0.0",
      "10.1.2.3",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "100.64.0.1",
      "100.127.255.255",
      "192.0.0.8",
      "192.0.2.1",
      "198.18.0.1",
      "198.19.0.1",
      "198.51.100.7",
      "192.88.99.1",
      "192.88.99.255",
      "203.0.113.9",
      "224.0.0.1",
      "255.255.255.255",
    ]) {
      assert.equal(isPrivateOrReservedIpv4(ip), true, ip);
    }
  });

  it("allows public IPv4, including the neighbours of each refused range", () => {
    for (const ip of ["8.8.8.8", "172.15.0.1", "172.32.0.1", "100.63.0.1", "100.128.0.1", "192.0.1.1", "198.20.0.1", "198.51.101.1", "203.0.114.1", "169.253.1.1", "192.169.0.1", "223.255.255.255", "203.1.113.1", "198.52.100.1", "192.88.98.1", "192.88.100.1", "192.89.99.1"]) {
      assert.equal(isPrivateOrReservedIpv4(ip), false, ip);
    }
  });

  it("fails closed on anything that is not a dotted quad", () => {
    for (const bad of ["256.1.1.1", "1.2.3", "a.b.c.d", ""]) assert.equal(isPrivateOrReservedIpv4(bad), true, bad);
  });

  it("refuses IPv6 loopback, unspecified, local, multicast, documentation, tunnels and embedded private IPv4", () => {
    for (const ip of [
      "::",
      "::1",
      "::ffff:127.0.0.1",
      "::ffff:a9fe:a9fe",
      "::127.0.0.1",
      "::ffff:0:7f00:1",
      "64:ff9b::a00:1",
      "64:ff9b:1::1",
      "2002:a00:1::",
      "2001::1",
      "2001:db8::1",
      "2001:10::1",
      "2001:1f:ffff::1",
      "fe80::1%eth0",
      "febf::1",
      "fec0::1",
      "feff:ffff::1",
      "fc00::1",
      "fd12:3456::1",
      "ff02::1",
      "100::1",
    ]) {
      assert.equal(isPrivateOrReservedIpv6(ip), true, ip);
    }
  });

  it("allows public IPv6, including public IPv4 embedded in each translated form", () => {
    for (const ip of ["2606:4700::1111", "2606:4700:0:0:0:0:0:1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::", "::ffff:0:808:808", "100:1::1", "2001:4860::8888", "2001:f:ffff::1", "2001:20::1"]) {
      assert.equal(isPrivateOrReservedIpv6(ip), false, ip);
    }
  });

  it("fails closed on malformed IPv6", () => {
    for (const bad of ["1::2::3", "1:2:3", "1:2:3:4:5:6:7:8:9", "::g", "x.1.2.3", "::ffff:999.1.1.1", "1:2:3:4:5:6:7::8"]) {
      assert.equal(isPrivateOrReservedIpv6(bad), true, bad);
    }
  });

  it("classifies either family, brackets allowed", () => {
    assert.equal(isPrivateOrReservedAddress("[::1]"), true);
    assert.equal(isPrivateOrReservedAddress("10.0.0.1"), true);
    assert.equal(isPrivateOrReservedAddress("8.8.4.4"), false);
  });
});

describe("internal host names", () => {
  it("refuses dotless names and private suffixes, trailing dots stripped", () => {
    for (const host of ["localhost", "localhost.", "metadata", "", "printer.local", "db.internal", "x.home.arpa", "a.localhost", "LOCALHOST..", "Printer.Local"]) {
      assert.equal(isInternalHostname(host), true, host);
    }
    for (const host of ["client.example.com", "example.com.", "local.example.com"]) assert.equal(isInternalHostname(host), false, host);
  });
});

describe("resolvePublicAddresses", () => {
  it("refuses an internal name without asking the resolver", async () => {
    let asked = 0;
    const result = await resolvePublicAddresses("metadata", async () => {
      asked += 1;
      return [];
    });
    assert.deepEqual(result, { ok: false, reason: "blocked" });
    assert.equal(asked, 0);
  });

  it("refuses a name when ANY of its addresses is private", async () => {
    const result = await resolvePublicAddresses("client.example.com", async () => [
      { address: "93.184.215.14", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ]);
    assert.deepEqual(result, { ok: false, reason: "blocked" });
  });

  it("answers unresolvable for no addresses or a resolver that throws", async () => {
    assert.deepEqual(await resolvePublicAddresses("client.example.com", async () => []), { ok: false, reason: "unresolvable" });
    const thrown = await resolvePublicAddresses("client.example.com", async () => {
      throw new Error("ENOTFOUND");
    });
    assert.deepEqual(thrown, { ok: false, reason: "unresolvable" });
  });

  it("returns the checked addresses, copied", async () => {
    const result = await resolvePublicAddresses("client.example.com", async () => [
      { address: "2606:4700::1111", family: 6, extra: true } as never,
    ]);
    assert.deepEqual(result, { ok: true, addresses: [{ address: "2606:4700::1111", family: 6 }] });
  });

  it("the system resolver answers every address (localhost comes from the hosts file)", async () => {
    const addresses = await systemResolver("localhost");
    assert.ok(addresses.length >= 1);
    assert.ok(addresses.every((a) => isPrivateOrReservedAddress(a.address)));
  });
});
