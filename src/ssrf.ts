/**
 * The SSRF guard in front of the client metadata fetch.
 *
 * An unauthenticated visitor to the consent page chooses the client_id URL, so
 * the fetch is an SSRF surface by construction. This module decides whether a
 * host may be fetched at all and which addresses the connection is pinned to:
 *
 *   - a host that names a machine inside a private network (dotless names,
 *     `.localhost`, `.local`, `.internal`, `.home.arpa`) is refused before any
 *     lookup;
 *   - the name is resolved once, through the resolver the caller supplies (the
 *     system resolver by default), and refused if ANY address is loopback,
 *     private, link-local, site-local, shared, reserved, documentation, multicast, or an
 *     IPv6 form that embeds one of those IPv4 addresses;
 *   - the fetch then connects to exactly those addresses (see pinned-get.ts),
 *     so a second lookup at connect time cannot rebind the name inward.
 *
 * There is no test-mode bypass. Tests inject a resolver.
 */
import { lookup } from "node:dns/promises";

export interface ResolvedAddress {
  address: string;
  /** 4 or 6. */
  family: number;
}

/** Resolves a host name to every address it has. */
export type HostResolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;

/** The system resolver, every address. */
export const systemResolver: HostResolver = (hostname) => lookup(hostname, { all: true, verbatim: true });

function ipv4Parts(host: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return null;
  const parts = match.slice(1).map(Number);
  return parts.some((part) => part > 255) ? null : parts;
}

/** Fails closed: anything that is not a dotted quad counts as private. */
export function isPrivateOrReservedIpv4(host: string): boolean {
  const parts = ipv4Parts(host);
  if (!parts) return true;
  const [a, b, c] = parts as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127) return true; // this network, private, loopback
  if (a === 169 && b === 254) return true; // link-local, cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // shared address space (CGNAT)
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // IETF special purpose, TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  return a >= 224; // multicast, reserved, broadcast
}

/** The 8 groups of an IPv6 address (zone id dropped, trailing dotted quad allowed), or null. */
function expandIpv6(raw: string): number[] | null {
  let addr = raw;
  const zone = addr.indexOf("%");
  if (zone !== -1) addr = addr.slice(0, zone);
  if (addr.includes(".")) {
    const lastColon = addr.lastIndexOf(":");
    const v4 = ipv4Parts(addr.slice(lastColon + 1));
    if (lastColon === -1 || !v4) return null;
    const [p0, p1, p2, p3] = v4 as [number, number, number, number];
    addr = `${addr.slice(0, lastColon + 1)}${((p0 << 8) | p1).toString(16)}:${((p2 << 8) | p3).toString(16)}`;
  }
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups: number[] = [];
  for (const group of [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail]) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    groups.push(parseInt(group, 16));
  }
  return groups;
}

/** Fails closed: an address that does not expand counts as private. */
export function isPrivateOrReservedIpv6(raw: string): boolean {
  const groups = expandIpv6(raw.toLowerCase());
  if (!groups) return true;
  const [g0, g1, g2, , g4, g5, g6, g7] = groups as [number, number, number, number, number, number, number, number];
  const zeroThrough = (end: number) => groups.slice(0, end).every((group) => group === 0);
  const embedded = (hi: number, lo: number) => isPrivateOrReservedIpv4(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);

  if (zeroThrough(7) && g7 <= 1) return true; // unspecified, loopback
  if (zeroThrough(5) && (g5 === 0xffff || g5 === 0)) return embedded(g6, g7); // IPv4-mapped, IPv4-compatible
  if (zeroThrough(4) && g4 === 0xffff && g5 === 0) return embedded(g6, g7); // IPv4-translated (SIIT)
  if (g0 === 0x64 && g1 === 0xff9b && groups.slice(2, 6).every((group) => group === 0)) return embedded(g6, g7); // NAT64
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 1) return true; // local-use NAT64
  if (g0 === 0x2002) return embedded(g1, g2); // 6to4
  if (g0 === 0x2001 && (g1 === 0 || g1 === 0xdb8)) return true; // Teredo, documentation
  if ((g0 & 0xffc0) === 0xfe80) return true; // link-local
  if ((g0 & 0xffc0) === 0xfec0) return true; // site-local (deprecated, still routed on some networks)
  if ((g0 & 0xfe00) === 0xfc00) return true; // unique local
  if ((g0 & 0xff00) === 0xff00) return true; // multicast
  return g0 === 0x100 && groups.slice(1, 4).every((group) => group === 0); // discard-only 100::/64
}

/** Any IP address literal, v4 or v6, brackets allowed. */
export function isPrivateOrReservedAddress(raw: string): boolean {
  const addr = raw.replace(/^\[/, "").replace(/]$/, "");
  return addr.includes(":") ? isPrivateOrReservedIpv6(addr) : isPrivateOrReservedIpv4(addr);
}

/**
 * Does this host name a machine inside a private network? Trailing dots are
 * stripped first (`localhost.` is localhost), and a dotless name is internal
 * (it resolves through search domains).
 */
export function isInternalHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.+$/, "");
  if (!host.includes(".")) return true;
  return /\.(localhost|local|internal|home\.arpa)$/.test(host);
}

export type GuardResult =
  | { ok: true; addresses: ResolvedAddress[] }
  | { ok: false; reason: "blocked" | "unresolvable" };

/**
 * Resolve `hostname` once and check every address. The caller connects to the
 * returned addresses and nothing else. `hostname` is a name, never an IP
 * literal: client_id URLs with an IP host are refused before this is called.
 */
export async function resolvePublicAddresses(hostname: string, resolver: HostResolver): Promise<GuardResult> {
  if (isInternalHostname(hostname)) return { ok: false, reason: "blocked" };
  let addresses: readonly ResolvedAddress[];
  try {
    addresses = await resolver(hostname);
  } catch {
    return { ok: false, reason: "unresolvable" };
  }
  if (addresses.length === 0) return { ok: false, reason: "unresolvable" };
  if (addresses.some((entry) => isPrivateOrReservedAddress(entry.address))) return { ok: false, reason: "blocked" };
  return { ok: true, addresses: addresses.map((entry) => ({ address: entry.address, family: entry.family })) };
}
