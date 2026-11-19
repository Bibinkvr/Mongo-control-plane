import { describe, expect, it } from "vitest";
import { isMongoAddressAllowed } from "../src/provisioning/network-guard.js";

describe("MongoDB outbound network policy", () => {
  it("blocks loopback and link-local metadata addresses by default", () => {
    for (const address of ["127.0.0.1", "169.254.169.254", "168.63.129.16", "::1", "fe80::1"]) {
      expect(isMongoAddressAllowed(address)).toBe(false);
    }
  });
  it("allows private addresses only with explicit operator policy", () => {
    expect(isMongoAddressAllowed("10.0.0.5")).toBe(false);
    expect(isMongoAddressAllowed("10.0.0.5", { allowPrivateNetworks: true })).toBe(true);
    expect(isMongoAddressAllowed("fd00::5", { allowPrivateNetworks: true })).toBe(true);
    expect(isMongoAddressAllowed("127.0.0.1", { allowPrivateNetworks: true })).toBe(false);
    expect(isMongoAddressAllowed("127.0.0.1", { allowLoopback: true })).toBe(true);
  });
  it("blocks documentation, multicast, and reserved address ranges", () => {
    for (const address of ["192.0.2.1", "198.51.100.2", "203.0.113.3", "224.0.0.1", "2001:db8::1", "ff02::1"]) {
      expect(isMongoAddressAllowed(address)).toBe(false);
    }
  });
  it("allows public unicast addresses", () => {
    expect(isMongoAddressAllowed("8.8.8.8")).toBe(true);
    expect(isMongoAddressAllowed("2606:4700:4700::1111")).toBe(true);
  });
});
