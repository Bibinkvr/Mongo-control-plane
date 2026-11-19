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
function inIpv4Range(parts: number[], first: number, second?: number, secondMask = 255): boolean {
  return parts[0] === first && (second === undefined || (parts[1]! & secondMask) === second);
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
  if (value.startsWith("fc") || value.startsWith("fd")) return policy.allowPrivateNetworks === true;
  if (/^fe[89ab]/.test(value) || value.startsWith("ff")) return false;
  if (value.startsWith("2001:db8:") || value.startsWith("2001:10:") || value.startsWith("2001:20:")) return false;
  if (value.startsWith("2002:") || value.startsWith("64:ff9b:")) return false;
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
