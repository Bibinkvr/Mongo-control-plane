import { randomBytes } from "node:crypto";
import type { Db, Document, MongoClient } from "mongodb";

export type SharedDatabaseIdentity = {
  projectId: string;
  databaseName: string;
  username: string;
  password: string;
  resourceId: string;
};

export type SharedDatabaseProvisioningResult = {
  databaseName: string;
  username: string;
  action: "created" | "reconciled";
};

export type SharedDatabaseRemovalResult = {
  databaseName: string;
  username: string;
  removed: boolean;
};

const MANAGED_BY = "mongo-control-plane";
const DATABASE_NAME_PATTERN = /^mcp_[a-f0-9]{16}_[a-f0-9]{16}$/;
const USERNAME_PATTERN = /^mcp_[a-f0-9]{32}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function assertIdentity(identity: SharedDatabaseIdentity): void {
  if (!UUID_PATTERN.test(identity.projectId) || !UUID_PATTERN.test(identity.resourceId)) {
    throw new Error("Project and resource IDs must be UUIDs.");
  }
  const expectedDatabase = `mcp_${identity.projectId.replaceAll("-", "").slice(0, 16).toLowerCase()}_${identity.resourceId.replaceAll("-", "").slice(0, 16).toLowerCase()}`;
  const expectedUsername = `mcp_${identity.resourceId.replaceAll("-", "").toLowerCase()}`;
  if (!DATABASE_NAME_PATTERN.test(identity.databaseName) || identity.databaseName !== expectedDatabase) {
    throw new Error("Managed MongoDB database name does not match the project and resource IDs.");
  }
  if (!USERNAME_PATTERN.test(identity.username) || identity.username !== expectedUsername) {
    throw new Error("Managed MongoDB username does not match the resource ID.");
  }
  if (identity.password.length < 32 || identity.password.length > 256) {
    throw new Error("Managed MongoDB password must contain between 32 and 256 characters.");
  }
}

/** Generates a high-entropy password suitable for a database-scoped application user. */
export function generateSharedDatabasePassword(): string {
  return randomBytes(32).toString("base64url");
}

/** Stable, collision-resistant names derived only from server-generated UUIDs. */
export function createSharedDatabaseIdentity(projectId: string, resourceId: string, password: string): SharedDatabaseIdentity {
  if (!UUID_PATTERN.test(projectId) || !UUID_PATTERN.test(resourceId)) {
    throw new Error("Project and resource IDs must be UUIDs.");
  }
  const projectPart = projectId.replaceAll("-", "").slice(0, 16).toLowerCase();
  const resourcePart = resourceId.replaceAll("-", "").slice(0, 16).toLowerCase();
  const identity = {
    projectId: projectId.toLowerCase(),
    databaseName: `mcp_${projectPart}_${resourcePart}`,
    username: `mcp_${resourceId.replaceAll("-", "").toLowerCase()}`,
    password,
    resourceId: resourceId.toLowerCase(),
  };
  assertIdentity(identity);
  return identity;
}

function isManagedUser(value: unknown, identity: SharedDatabaseIdentity): boolean {
  if (typeof value !== "object" || value === null) return false;
  const customData = (value as { customData?: unknown }).customData;
  if (typeof customData !== "object" || customData === null) return false;
  const metadata = customData as { managedBy?: unknown; projectId?: unknown; resourceId?: unknown };
  return metadata.managedBy === MANAGED_BY && metadata.projectId === identity.projectId && metadata.resourceId === identity.resourceId;
}

async function findUser(database: Db, username: string): Promise<unknown | undefined> {
  const result = await database.command({
    usersInfo: username,
    showCredentials: false,
    showPrivileges: false,
  });
  const users = (result as { users?: unknown }).users;
  if (!Array.isArray(users)) throw new Error("MongoDB returned an invalid usersInfo response.");
  return users[0];
}

function userRoles(databaseName: string): Document[] {
  return [{ role: "readWrite", db: databaseName }];
}

function userMetadata(identity: SharedDatabaseIdentity): Document {
  return { managedBy: MANAGED_BY, projectId: identity.projectId, resourceId: identity.resourceId };
}

/**
 * Creates or reconciles a database-scoped application user.
 *
 * The password must be durably encrypted by the caller before this operation
 * starts. A retry may safely reconcile only a user carrying this platform's
 * ownership marker; an unrelated pre-existing user is never modified.
 */
export async function provisionSharedDatabaseUser(
  adminClient: MongoClient,
  identity: SharedDatabaseIdentity,
): Promise<SharedDatabaseProvisioningResult> {
  assertIdentity(identity);
  const target = adminClient.db(identity.databaseName);
  const existing = await findUser(target, identity.username);
  if (existing !== undefined) {
    if (!isManagedUser(existing, identity)) {
      throw new Error("A MongoDB user with this name exists but is not owned by this resource.");
    }
    await target.command({
      updateUser: identity.username,
      pwd: identity.password,
      roles: userRoles(identity.databaseName),
      customData: userMetadata(identity),
      mechanisms: ["SCRAM-SHA-256"],
      writeConcern: { w: "majority" },
    });
    return { databaseName: identity.databaseName, username: identity.username, action: "reconciled" };
  }

  try {
    await target.command({
      createUser: identity.username,
      pwd: identity.password,
      roles: userRoles(identity.databaseName),
      customData: userMetadata(identity),
      mechanisms: ["SCRAM-SHA-256"],
      writeConcern: { w: "majority" },
    });
    return { databaseName: identity.databaseName, username: identity.username, action: "created" };
  } catch (error) {
    // Another worker may have won the create race. Re-read ownership before
    // deciding whether a retry can safely reconcile the user.
    const racedUser = await findUser(target, identity.username);
    if (racedUser === undefined) throw error;
    if (!isManagedUser(racedUser, identity)) {
      throw new Error("A MongoDB user with this name exists but is not owned by this resource.");
    }
    await target.command({
      updateUser: identity.username,
      pwd: identity.password,
      roles: userRoles(identity.databaseName),
      customData: userMetadata(identity),
      mechanisms: ["SCRAM-SHA-256"],
      writeConcern: { w: "majority" },
    });
    return { databaseName: identity.databaseName, username: identity.username, action: "reconciled" };
  }
}

/** Removes only a user whose custom ownership marker matches the resource. */
export async function removeSharedDatabaseUser(
  adminClient: MongoClient,
  identity: SharedDatabaseIdentity,
): Promise<SharedDatabaseRemovalResult> {
  assertIdentity(identity);
  const target = adminClient.db(identity.databaseName);
  const existing = await findUser(target, identity.username);
  if (existing === undefined) {
    return { databaseName: identity.databaseName, username: identity.username, removed: false };
  }
  if (!isManagedUser(existing, identity)) {
    throw new Error("Refusing to remove a MongoDB user not owned by this resource.");
  }
  await target.command({
    dropUser: identity.username,
    writeConcern: { w: "majority" },
  });
  return { databaseName: identity.databaseName, username: identity.username, removed: true };
}


export type SharedDatabaseBackupIdentity = {
  projectId: string;
  databaseName: string;
  username: string;
  password: string;
  resourceId: string;
};

const BACKUP_USERNAME_PATTERN = /^bkp_[a-f0-9]{32}$/;

export function createSharedDatabaseBackupIdentity(
  projectId: string,
  resourceId: string,
  password: string,
): SharedDatabaseBackupIdentity {
  if (!UUID_PATTERN.test(projectId) || !UUID_PATTERN.test(resourceId)) {
    throw new Error("Project and resource IDs must be UUIDs.");
  }
  const projectPart = projectId.replaceAll("-", "").slice(0, 16).toLowerCase();
  const resourcePart = resourceId.replaceAll("-", "").slice(0, 16).toLowerCase();
  const identity = {
    projectId: projectId.toLowerCase(),
    databaseName: `mcp_${projectPart}_${resourcePart}`,
    username: `bkp_${resourceId.replaceAll("-", "").toLowerCase()}`,
    password,
    resourceId: resourceId.toLowerCase(),
  };
  if (!BACKUP_USERNAME_PATTERN.test(identity.username)
    || password.length < 32 || password.length > 256) {
    throw new Error("Managed backup database identity is invalid.");
  }
  return identity;
}

function assertBackupIdentity(identity: SharedDatabaseBackupIdentity): void {
  if (!UUID_PATTERN.test(identity.projectId) || !UUID_PATTERN.test(identity.resourceId)) {
    throw new Error("Project and resource IDs must be UUIDs.");
  }
  const expectedDatabase = `mcp_${identity.projectId.replaceAll("-", "").slice(0, 16).toLowerCase()}_${identity.resourceId.replaceAll("-", "").slice(0, 16).toLowerCase()}`;
  const expectedUsername = `bkp_${identity.resourceId.replaceAll("-", "").toLowerCase()}`;
  if (identity.databaseName !== expectedDatabase || !BACKUP_USERNAME_PATTERN.test(identity.username)
    || identity.username !== expectedUsername || identity.password.length < 32 || identity.password.length > 256) {
    throw new Error("Managed backup database identity is invalid.");
  }
}

function isManagedBackupUser(value: unknown, identity: SharedDatabaseBackupIdentity): boolean {
  if (typeof value !== "object" || value === null) return false;
  const customData = (value as { customData?: unknown }).customData;
  if (typeof customData !== "object" || customData === null) return false;
  const metadata = customData as { managedBy?: unknown; projectId?: unknown; resourceId?: unknown; managedRole?: unknown };
  return metadata.managedBy === MANAGED_BY
    && metadata.projectId === identity.projectId
    && metadata.resourceId === identity.resourceId
    && metadata.managedRole === "backup";
}

function backupUserMetadata(identity: SharedDatabaseBackupIdentity): Document {
  return { managedBy: MANAGED_BY, projectId: identity.projectId, resourceId: identity.resourceId, managedRole: "backup" };
}

/** Creates or reconciles a database-scoped read-only user for mongodump. */
export async function provisionSharedDatabaseBackupUser(
  adminClient: MongoClient,
  identity: SharedDatabaseBackupIdentity,
): Promise<SharedDatabaseProvisioningResult> {
  assertBackupIdentity(identity);
  const target = adminClient.db(identity.databaseName);
  const existing = await findUser(target, identity.username);
  const command = {
    pwd: identity.password,
    roles: [{ role: "read", db: identity.databaseName }],
    customData: backupUserMetadata(identity),
    mechanisms: ["SCRAM-SHA-256"],
    writeConcern: { w: "majority" },
  };
  if (existing !== undefined) {
    if (!isManagedBackupUser(existing, identity)) {
      throw new Error("A MongoDB backup user with this name exists but is not owned by this resource.");
    }
    await target.command({ updateUser: identity.username, ...command });
    return { databaseName: identity.databaseName, username: identity.username, action: "reconciled" };
  }
  try {
    await target.command({ createUser: identity.username, ...command });
    return { databaseName: identity.databaseName, username: identity.username, action: "created" };
  } catch (error) {
    const racedUser = await findUser(target, identity.username);
    if (racedUser === undefined) throw error;
    if (!isManagedBackupUser(racedUser, identity)) {
      throw new Error("A MongoDB backup user with this name exists but is not owned by this resource.");
    }
    await target.command({ updateUser: identity.username, ...command });
    return { databaseName: identity.databaseName, username: identity.username, action: "reconciled" };
  }
}

/** Removes only a read-only backup user carrying this resource's ownership marker. */
export async function removeSharedDatabaseBackupUser(
  adminClient: MongoClient,
  identity: SharedDatabaseBackupIdentity,
): Promise<SharedDatabaseRemovalResult> {
  assertBackupIdentity(identity);
  const target = adminClient.db(identity.databaseName);
  const existing = await findUser(target, identity.username);
  if (existing === undefined) {
    return { databaseName: identity.databaseName, username: identity.username, removed: false };
  }
  if (!isManagedBackupUser(existing, identity)) {
    throw new Error("Refusing to remove a MongoDB backup user not owned by this resource.");
  }
  await target.command({ dropUser: identity.username, writeConcern: { w: "majority" } });
  return { databaseName: identity.databaseName, username: identity.username, removed: true };
}
