import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import type { MongoClientOptions } from "mongodb";

export type MongoNetworkPolicy = {
  allowPrivateNetworks?: boolean;
  allowLoopback?: boolean;
};

function ipv4Parts(address: string): number[] | undefined {
  if (isIP(address) !== 4) return undefined;
  const parts = address.split(".").map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? parts : undefined;
}
function isAllowedIpv4(address: string, policy: MongoNetworkPolicy): boolean {
  const p = ipv4Parts(address);
  if (!p) return false;
  const [a, b, c] = p as [number, number, number, number];
  const loopback = a === 127;
  if (loopback) return policy.allowLoopback === true;
  if (a === 169 && b === 254) return false; // Link-local and cloud metadata endpoints.
  if (a === 0 || a >= 224 || (a === 255 && b === 255 && c === 255)) return false;
  if ((a === 100 && b! >= 64 && b! <= 127)
    || (a === 168 && b === 63 && c === 129 && p[3] === 16)
    || (a === 100 && b === 100 && c === 100 && p[3] === 200)) return false;
  if (a === 192 && (b === 0 || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  const privateAddress = a === 10 || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && b === 168);
  return privateAddress ? policy.allowPrivateNetworks === true : true;
}

function mappedIpv4(address: string): string | undefined {
  const normalized = address.toLowerCase().split("%")[0] ?? address.toLowerCase();
  const dotted = normalized.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted) return dotted[1];
  const hex = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (!hex) return undefined;
  const high = Number.parseInt(hex[1]!, 16);
  const low = Number.parseInt(hex[2]!, 16);
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}
function isAllowedIpv6(address: string, policy: MongoNetworkPolicy): boolean {
  const value = address.toLowerCase().split("%")[0] ?? address.toLowerCase();
  if (value === "::") return false;
  if (value === "::1") return policy.allowLoopback === true;
  const mapped = mappedIpv4(value);
  if (mapped) return isAllowedIpv4(mapped, policy);
  if (value.startsWith("::") || value.startsWith("fd00:ec2::254")) return false;

  // Only global-unicast 2000::/3 is eligible. This rejects ULA, link-local,
  // multicast, unspecified, site-local, NAT64 and other special-purpose space.
  const halves = value.split("::");
  if (halves.length > 2) return false;
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return false;
  const groups = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return false;
  const first = Number.parseInt(groups[0]!, 16);
  const second = Number.parseInt(groups[1]!, 16);
  const third = Number.parseInt(groups[2]!, 16);
  if (first < 0x2000 || first > 0x3fff) return false;
  if (first === 0x2001 && (
    second === 0x0000 || second === 0x0002 || second === 0x0db8
    || (second & 0xfff0) === 0x0010 || (second & 0xfff0) === 0x0020
  )) return false;
  if (first === 0x2002) return false; // 6to4 embeds an IPv4 destination.
  if (first === 0x2001 && second === 0x0000 && third === 0) return false;
  return true;
}

export function isMongoAddressAllowed(address: string, policy: MongoNetworkPolicy = {}): boolean {
  const version = isIP(address);
  if (version === 4) return isAllowedIpv4(address, policy);
  if (version === 6) return isAllowedIpv6(address, policy);
  return false;
}

/**
 * Re-resolves every socket destination and passes only vetted IPs to net.connect.
 * This pins the actual connection to the addresses checked here and blocks DNS
 * rebinding to loopback, link-local, metadata, multicast, and reserved ranges.
 */
export function createSafeMongoLookup(policy: MongoNetworkPolicy = {}): NonNullable<MongoClientOptions["lookup"]> {
  return (hostname, options, callback) => {
    const family = typeof options === "number" ? options : options.family;
    const all = typeof options !== "number" && options.all === true;
    dnsLookup(hostname, { ...(family ? { family } : {}), all: true, verbatim: true }, (error, addresses) => {
      if (error) {
        callback(error, "", 0);
        return;
      }
      const safe = addresses.filter((item) => isMongoAddressAllowed(item.address, policy));
      if (safe.length !== addresses.length || safe.length === 0) {
        const blocked = Object.assign(new Error("MongoDB target resolved to a prohibited network address."), { code: "EACCES" });
        callback(blocked, "", 0);
        return;
      }
      if (all) callback(null, safe);
      else callback(null, safe[0]!.address, safe[0]!.family);
    });
  };
}
