import { describe, expect, it } from "vitest";
import { hasProjectPermission, PROJECT_PERMISSIONS } from "../src/auth/permissions.js";

describe("project permission matrix", () => {
  it("grants project administrators every declared permission", () => {
    for (const permission of PROJECT_PERMISSIONS) {
      expect(hasProjectPermission("project_admin", permission)).toBe(true);
    }
  });

  it("allows developers to read and modify database data but not administer members or backups", () => {
    expect(hasProjectPermission("developer", "database:read")).toBe(true);
    expect(hasProjectPermission("developer", "database:write")).toBe(true);
    expect(hasProjectPermission("developer", "members:manage")).toBe(false);
    expect(hasProjectPermission("developer", "backup:manage")).toBe(false);
  });

  it("restricts read-only users to read permissions", () => {
    expect(hasProjectPermission("read_only", "database:read")).toBe(true);
    expect(hasProjectPermission("read_only", "database:write")).toBe(false);
    expect(hasProjectPermission("read_only", "connection:manage")).toBe(false);
  });

  it("does not grant permissions to unknown roles", () => {
    expect(hasProjectPermission("unknown", "project:read")).toBe(false);
  });

  it("grants platform administrators every project permission", () => {
    for (const permission of PROJECT_PERMISSIONS) {
      expect(hasProjectPermission("platform_admin", permission)).toBe(true);
    }
  });
});
