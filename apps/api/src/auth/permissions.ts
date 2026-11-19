export const PROJECT_PERMISSIONS = [
  "project:read",
  "members:read",
  "members:manage",
  "connection:read",
  "connection:manage",
  "connection:use",
  "database:read",
  "database:write",
  "database:admin",
  "database:use",
  "backup:read",
  "backup:manage",
  "audit:read",
] as const;

export type ProjectPermission = (typeof PROJECT_PERMISSIONS)[number];
export type ProjectRole = "project_admin" | "developer" | "read_only" | "platform_admin";

const ROLE_PERMISSIONS: Record<Exclude<ProjectRole, "platform_admin">, ReadonlySet<ProjectPermission>> = {
  project_admin: new Set(PROJECT_PERMISSIONS),
  developer: new Set([
    "project:read", "members:read", "connection:read", "connection:use",
    "database:read", "database:write", "database:use", "backup:read",
  ]),
  read_only: new Set([
    "project:read", "members:read", "connection:read",
    "database:read", "backup:read",
  ]),
};

export function hasProjectPermission(role: string, permission: ProjectPermission): boolean {
  if (role === "platform_admin" || role === "project_admin") return true;
  if (role !== "developer" && role !== "read_only") return false;
  return ROLE_PERMISSIONS[role].has(permission);
}
