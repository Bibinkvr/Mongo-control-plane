import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Pool } from "pg";
import { resolveSession } from "../auth/router.js";
import { hasProjectPermission } from "../auth/permissions.js";
import { encryptConnectionUri, parseMongoConnectionUri, rewrapConnectionSecret, type EncryptionKeyring, type EncryptedConnectionSecret } from "./crypto.js";

const createSchema = z.object({
  name: z.string().trim().min(1).max(100),
  kind: z.enum(["shared", "dedicated", "atlas"]),
  uri: z.string().min(10).max(16_384),
}).strict();

type Caller = { id: string; is_platform_admin: boolean };
type DbRow = EncryptedConnectionSecret & { id: string; name: string; kind: string; host_label: string; status: string; created_at: Date; updated_at: Date };

function caller(response: Response): Caller { return response.locals["connectionCaller"] as Caller; }
function safeMetadata(row: DbRow) {
  return { id: row.id, name: row.name, kind: row.kind, hostLabel: row.host_label, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at };
}
const columns = "id, name, kind, host_label, status, secret_ciphertext AS ciphertext, secret_nonce AS nonce, secret_auth_tag AS \"authTag\", wrapped_dek AS \"wrappedDek\", wrap_nonce AS \"wrapNonce\", wrap_auth_tag AS \"wrapAuthTag\", key_version AS \"keyVersion\", created_at, updated_at";

async function projectRole(pool: Pool, projectId: string, user: Caller): Promise<string | null> {
  const result = await pool.query<{ role: string }>(
    `SELECT COALESCE(pm.role, 'platform_admin') AS role
       FROM projects p JOIN users u ON u.id = $2
       LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $2
      WHERE p.id = $1 AND (u.is_platform_admin = true OR pm.user_id = $2) LIMIT 1`,
    [projectId, user.id],
  );
  return result.rows[0]?.role ?? null;
}

export function createConnectionsRouter(pool: Pool, keyring: EncryptionKeyring): Router {
  const router = Router();
  router.use((_request, response, next) => { response.setHeader("Cache-Control", "no-store"); next(); });
  router.use(async (request: Request, response: Response, next: NextFunction) => {
    try {
      const user = await resolveSession(pool, request);
      if (!user) { response.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Authentication is required." } }); return; }
      response.locals["connectionCaller"] = { id: user.id, is_platform_admin: user.is_platform_admin };
      next();
    } catch (error) { next(error); }
  });

  router.get("/:projectId/connections", async (request, response) => {
    const id = z.string().uuid().safeParse(request.params["projectId"]);
    if (!id.success) { response.status(400).json({ error: { code: "INVALID_PROJECT_ID", message: "The project ID is invalid." } }); return; }
    const user = caller(response);
    const role = await projectRole(pool, id.data, user);
    if (!role) { response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } }); return; }
    if (!hasProjectPermission(role, "connection:read")) { response.status(403).json({ error: { code: "FORBIDDEN", message: "Connection read permission is required." } }); return; }
    const result = await pool.query<DbRow>(
      `SELECT id, name, kind, host_label, status, created_at, updated_at
         FROM connection_targets WHERE project_id = $1 ORDER BY created_at DESC`, [id.data],
    );
    response.status(200).json({ connections: result.rows.map((row) => safeMetadata(row)) });
  });

  router.post("/:projectId/connections", async (request, response) => {
    const id = z.string().uuid().safeParse(request.params["projectId"]);
    const body = createSchema.safeParse(request.body);
    if (!id.success) { response.status(400).json({ error: { code: "INVALID_PROJECT_ID", message: "The project ID is invalid." } }); return; }
    if (!body.success) { response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Provide a name, supported connection kind, and MongoDB URI." } }); return; }
    let hostLabel: string;
    let encrypted: EncryptedConnectionSecret;
    try {
      hostLabel = parseMongoConnectionUri(body.data.uri).hostLabel;
      encrypted = encryptConnectionUri(body.data.uri, keyring);
    } catch {
      response.status(400).json({ error: { code: "INVALID_MONGODB_URI", message: "The MongoDB connection URI is invalid or unsupported." } });
      return;
    }
    const user = caller(response);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await client.query("SELECT id FROM projects WHERE id = $1 FOR UPDATE", [id.data]);
      if (!project.rows[0]) { await client.query("ROLLBACK"); response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } }); return; }
      const membership = await client.query<{ role: string }>("SELECT role FROM project_memberships WHERE project_id = $1 AND user_id = $2", [id.data, user.id]);
      const role = user.is_platform_admin ? "platform_admin" : membership.rows[0]?.role;
      if (!role) { await client.query("ROLLBACK"); response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } }); return; }
      if (!hasProjectPermission(role, "connection:manage")) { await client.query("ROLLBACK"); response.status(403).json({ error: { code: "FORBIDDEN", message: "Connection management permission is required." } }); return; }
      const inserted = await client.query<DbRow>(
        `INSERT INTO connection_targets
          (project_id, name, kind, host_label, secret_ciphertext, secret_nonce, secret_auth_tag,
           wrapped_dek, wrap_nonce, wrap_auth_tag, key_version, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         RETURNING id, name, kind, host_label, status, created_at, updated_at`,
        [id.data, body.data.name, body.data.kind, hostLabel, encrypted.ciphertext, encrypted.nonce, encrypted.authTag,
         encrypted.wrappedDek, encrypted.wrapNonce, encrypted.wrapAuthTag, encrypted.keyVersion, user.id],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
         VALUES ($1,$2,'connection.create','connection',$3,jsonb_build_object('kind',$4::text,'hostLabel',$5::text))`,
        [user.id, id.data, inserted.rows[0]?.id, body.data.kind, hostLabel],
      );
      await client.query("COMMIT");
      response.status(201).json({ connection: safeMetadata(inserted.rows[0] as DbRow) });
    } catch (error) {
      await client.query("ROLLBACK");
      if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
        response.status(409).json({ error: { code: "CONNECTION_NAME_TAKEN", message: "A connection with this name already exists in the project." } });
        return;
      }
      throw error;
    } finally { client.release(); }
  });

  router.post("/:projectId/connections/:connectionId/rotate-key", async (request, response) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const connectionId = z.string().uuid().safeParse(request.params["connectionId"]);
    if (!projectId.success || !connectionId.success) { response.status(400).json({ error: { code: "INVALID_ID", message: "A project or connection ID is invalid." } }); return; }
    const user = caller(response);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const membership = await client.query<{ role: string }>(
        `SELECT COALESCE(pm.role, 'platform_admin') AS role
           FROM projects p JOIN users u ON u.id = $2
           LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $2
          WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id = $2) FOR UPDATE OF p`,
        [projectId.data, user.id],
      );
      if (!membership.rows[0]) { await client.query("ROLLBACK"); response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } }); return; }
      if (!hasProjectPermission(membership.rows[0].role, "connection:manage")) { await client.query("ROLLBACK"); response.status(403).json({ error: { code: "FORBIDDEN", message: "Connection management permission is required." } }); return; }
      const selected = await client.query<DbRow>(`SELECT ${columns} FROM connection_targets WHERE id = $1 AND project_id = $2 FOR UPDATE`, [connectionId.data, projectId.data]);
      const row = selected.rows[0];
      if (!row) { await client.query("ROLLBACK"); response.status(404).json({ error: { code: "CONNECTION_NOT_FOUND", message: "The connection was not found." } }); return; }
      const next = rewrapConnectionSecret(row, keyring);
      if (next.keyVersion !== row.keyVersion) {
        await client.query(
          `UPDATE connection_targets SET wrapped_dek=$3, wrap_nonce=$4, wrap_auth_tag=$5, key_version=$6, updated_at=now()
            WHERE id=$1 AND project_id=$2`,
          [connectionId.data, projectId.data, next.wrappedDek, next.wrapNonce, next.wrapAuthTag, next.keyVersion],
        );
        await client.query(
          `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
           VALUES ($1,$2,'connection.key.rotate','connection',$3,jsonb_build_object('fromVersion',$4::int,'toVersion',$5::int))`,
          [user.id, projectId.data, connectionId.data, row.keyVersion, next.keyVersion],
        );
      }
      await client.query("COMMIT");
      response.status(200).json({ connection: safeMetadata(row), keyVersion: next.keyVersion, rotated: next.keyVersion !== row.keyVersion });
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  });

  router.patch("/:projectId/connections/:connectionId", async (request, response) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const connectionId = z.string().uuid().safeParse(request.params["connectionId"]);
    const body = z.object({
      name: z.string().trim().min(1).max(100).optional(),
      status: z.enum(["configured", "disabled"]).optional(),
    }).strict().refine((value) => value.name !== undefined || value.status !== undefined).safeParse(request.body);
    if (!projectId.success || !connectionId.success) {
      response.status(400).json({ error: { code: "INVALID_ID", message: "A project or connection ID is invalid." } });
      return;
    }
    if (!body.success) {
      response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Provide a valid connection name or status." } });
      return;
    }
    const user = caller(response);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const membership = await client.query<{ role: string }>(
        `SELECT COALESCE(pm.role, 'platform_admin') AS role
           FROM projects p JOIN users u ON u.id = $2
           LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $2
          WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id = $2) FOR UPDATE OF p`,
        [projectId.data, user.id],
      );
      if (!membership.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      if (!hasProjectPermission(membership.rows[0].role, "connection:manage")) {
        await client.query("ROLLBACK");
        response.status(403).json({ error: { code: "FORBIDDEN", message: "Connection management permission is required." } });
        return;
      }
      const updated = await client.query<DbRow>(
        `UPDATE connection_targets
            SET name = COALESCE($3, name),
                status = COALESCE($4, status),
                updated_at = now()
          WHERE id = $1 AND project_id = $2
          RETURNING id, name, kind, host_label, status, created_at, updated_at`,
        [connectionId.data, projectId.data, body.data.name ?? null, body.data.status ?? null],
      );
      const row = updated.rows[0];
      if (!row) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "CONNECTION_NOT_FOUND", message: "The connection was not found." } });
        return;
      }
      await client.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
         VALUES ($1,$2,'connection.update','connection',$3,$4::jsonb)`,
        [user.id, projectId.data, connectionId.data, JSON.stringify({
          ...(body.data.name !== undefined ? { name: body.data.name } : {}),
          ...(body.data.status !== undefined ? { status: body.data.status } : {}),
        })],
      );
      await client.query("COMMIT");
      response.status(200).json({ connection: safeMetadata(row) });
    } catch (error) {
      await client.query("ROLLBACK");
      if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
        response.status(409).json({ error: { code: "CONNECTION_NAME_TAKEN", message: "A connection with this name already exists in the project." } });
        return;
      }
      throw error;
    } finally { client.release(); }
  });

  router.delete("/:projectId/connections/:connectionId", async (request, response) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const connectionId = z.string().uuid().safeParse(request.params["connectionId"]);
    if (!projectId.success || !connectionId.success) { response.status(400).json({ error: { code: "INVALID_ID", message: "A project or connection ID is invalid." } }); return; }
    const user = caller(response);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const membership = await client.query<{ role: string }>(
        `SELECT COALESCE(pm.role, 'platform_admin') AS role
           FROM projects p JOIN users u ON u.id = $2
           LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $2
          WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id = $2) FOR UPDATE OF p`,
        [projectId.data, user.id],
      );
      if (!membership.rows[0]) { await client.query("ROLLBACK"); response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } }); return; }
      if (!hasProjectPermission(membership.rows[0].role, "connection:manage")) { await client.query("ROLLBACK"); response.status(403).json({ error: { code: "FORBIDDEN", message: "Connection management permission is required." } }); return; }
      const deleted = await client.query("DELETE FROM connection_targets WHERE id=$1 AND project_id=$2 RETURNING id", [connectionId.data, projectId.data]);
      if (!deleted.rows[0]) { await client.query("ROLLBACK"); response.status(404).json({ error: { code: "CONNECTION_NOT_FOUND", message: "The connection was not found." } }); return; }
      await client.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id)
         VALUES ($1,$2,'connection.delete','connection',$3)`,
        [user.id, projectId.data, connectionId.data],
      );
      await client.query("COMMIT");
      response.status(204).end();
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  });

  return router;
}
