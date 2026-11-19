import { describe, expect, it } from "vitest";
import { isSafeCollectionName, isSafeDocument } from "../src/workspace/service.js";

describe("MongoDB workspace input validation", () => {
  it("accepts normal collection names and rejects reserved or unsafe names", () => {
    expect(isSafeCollectionName("customers")).toBe(true);
    expect(isSafeCollectionName("customer_events-2026")).toBe(true);
    expect(isSafeCollectionName("system.users")).toBe(false);
    expect(isSafeCollectionName("$cmd")).toBe(false);
    expect(isSafeCollectionName(".hidden")).toBe(false);
    expect(isSafeCollectionName("")).toBe(false);
    expect(isSafeCollectionName("x".repeat(121))).toBe(false);
  });

  it("accepts plain nested JSON documents", () => {
    expect(isSafeDocument({ name: "Ada", profile: { active: true }, tags: ["a", "b"] })).toBe(true);
  });

  it("rejects operator keys, dotted keys, prototype keys and excessive nesting", () => {
    expect(isSafeDocument({ $where: "sleep(1000)" })).toBe(false);
    expect(isSafeDocument({ "profile.name": "Ada" })).toBe(false);
    expect(isSafeDocument({ profile: { $ne: null } })).toBe(false);
    expect(isSafeDocument({ constructor: { prototype: {} } })).toBe(false);
    let deep: Record<string, unknown> = {};
    let cursor = deep;
    for (let i = 0; i < 22; i += 1) {
      const next: Record<string, unknown> = {};
      cursor["child"] = next;
      cursor = next;
    }
    expect(isSafeDocument(deep)).toBe(false);
  });
});
