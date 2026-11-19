import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Pool } from "pg";
import { resolveSession } from "../auth/router.js";

const createProjectSchema = z.object({
  name: z.string().trim().min(1).max(100),
  slug: z.string().trim().min(1).max(63).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/).optional(),
}).strict();

type ProjectUser = { id: string; is_platform_admin: boolean };

function slugify(value: string): string {
  return value.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 63).replace(/-$/g, "");
}

function currentUser(response: Response): ProjectUser {
  return response.locals["projectUser"] as ProjectUser;
}

export function createProjectsRouter(pool: Pool): Router {
  const router = Router();
  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.use(async (request: Request, response: Response, next: NextFunction) => {
    try {
      const user = await resolveSession(pool, request);
      if (!user) {
        response.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Authentication is required." } });
        return;
      }
      response.locals["projectUser"] = { id: user.id, is_platform_admin: user.is_platform_admin };
      next();
    } catch (error) {
      next(error);
    }
  });

  router.get("/", async (_request, response) => {
    const user = currentUser(response);
    const result = await pool.query(
      `SELECT p.id, p.name, p.slug, p.created_at,
              COALESCE(pm.role, 'platform_admin') AS role
         FROM projects p
         JOIN users u ON u.id = $1
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $1
        WHERE u.is_platform_admin = true OR pm.user_id = $1
        ORDER BY p.created_at DESC`,
      [user.id],
    );
    response.status(200).json({ projects: result.rows });
  });

  router.post("/", async (request, response) => {
    const parsed = createProjectSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Provide a valid project name and optional URL-safe slug." } });
      return;
    }

    const user = currentUser(response);
    const name = parsed.data.name;
    const slug = parsed.data.slug ?? slugify(name);
    if (!slug) {
      response.status(400).json({ error: { code: "INVALID_SLUG", message: "The project name cannot be converted into a valid slug." } });
      return;
    }

    try {
      const result = await pool.query(
        `WITH new_project AS (
           INSERT INTO projects (name, slug, created_by)
           VALUES ($1, $2, $3)
           RETURNING id, name, slug, created_at
         ),
         new_membership AS (
           INSERT INTO project_memberships (project_id, user_id, role, created_by)
           SELECT id, $3, 'project_admin', $3 FROM new_project
           RETURNING project_id
         ),
         audit AS (
           INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
           SELECT $3, project_id, 'project.create', 'project', project_id::text,
                  jsonb_build_object('slug', $2)
             FROM new_membership
           RETURNING id
         )
         SELECT p.id, p.name, p.slug, p.created_at, 'project_admin' AS role
           FROM new_project p
           JOIN new_membership m ON m.project_id = p.id
           CROSS JOIN audit`,
        [name, slug, user.id],
      );
      response.status(201).json({ project: result.rows[0] });
    } catch (error) {
      if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
        response.status(409).json({ error: { code: "PROJECT_SLUG_TAKEN", message: "A project with this slug already exists." } });
        return;
      }
      throw error;
    }
  });

  router.get("/:projectId", async (request, response) => {
    const parsedId = z.string().uuid().safeParse(request.params["projectId"]);
    if (!parsedId.success) {
      response.status(400).json({ error: { code: "INVALID_PROJECT_ID", message: "The project ID is invalid." } });
      return;
    }
    const user = currentUser(response);
    const result = await pool.query(
      `SELECT p.id, p.name, p.slug, p.created_at,
              COALESCE(pm.role, 'platform_admin') AS role
         FROM projects p
         JOIN users u ON u.id = $2
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $2
        WHERE p.id = $1 AND (u.is_platform_admin = true OR pm.user_id = $2)
        LIMIT 1`,
      [parsedId.data, user.id],
    );
    if (!result.rows[0]) {
      response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
      return;
    }
    response.status(200).json({ project: result.rows[0] });
  });


  router.get("/:projectId/members", async (request, response) => {
    const parsedId = z.string().uuid().safeParse(request.params["projectId"]);
    if (!parsedId.success) {
      response.status(400).json({ error: { code: "INVALID_PROJECT_ID", message: "The project ID is invalid." } });
      return;
    }
    const user = currentUser(response);
    const access = await pool.query<{ role: string }>(
      `SELECT COALESCE(pm.role, 'platform_admin') AS role
         FROM projects p
         JOIN users caller ON caller.id = $2
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $2
        WHERE p.id = $1 AND (caller.is_platform_admin = true OR pm.user_id = $2)
        LIMIT 1`,
      [parsedId.data, user.id],
    );
    if (!access.rows[0]) {
      response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
      return;
    }
    const members = await pool.query(
      `SELECT u.id, u.email_normalized AS email, u.display_name AS "displayName",
              pm.role, pm.created_at AS "joinedAt"
         FROM project_memberships pm
         JOIN users u ON u.id = pm.user_id
        WHERE pm.project_id = $1
        ORDER BY pm.created_at ASC`,
      [parsedId.data],
    );
    response.status(200).json({ members: members.rows });
  });

  router.post("/:projectId/members", async (request, response) => {
    const parsedId = z.string().uuid().safeParse(request.params["projectId"]);
    const body = z.object({
      email: z.string().trim().email().max(254),
      role: z.enum(["project_admin", "developer", "read_only"]),
    }).strict().safeParse(request.body);
    if (!parsedId.success) {
      response.status(400).json({ error: { code: "INVALID_PROJECT_ID", message: "The project ID is invalid." } });
      return;
    }
    if (!body.success) {
      response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Provide a valid member email and project role." } });
      return;
    }

    const user = currentUser(response);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await client.query("SELECT id FROM projects WHERE id = $1 FOR UPDATE", [parsedId.data]);
      if (!project.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      const access = await client.query<{ role: string }>(
        "SELECT role FROM project_memberships WHERE project_id = $1 AND user_id = $2",
        [parsedId.data, user.id],
      );
      if (!user.is_platform_admin && !access.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      if (!user.is_platform_admin && access.rows[0]?.role !== "project_admin") {
        await client.query("ROLLBACK");
        response.status(403).json({ error: { code: "FORBIDDEN", message: "Project administrator permission is required." } });
        return;
      }

      const target = await client.query<{ id: string }>(
        "SELECT id FROM users WHERE email_normalized = $1 AND status = 'active' LIMIT 1",
        [body.data.email.toLowerCase()],
      );
      if (!target.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "USER_NOT_FOUND", message: "No active user exists with that email." } });
        return;
      }

      const inserted = await client.query(
        `INSERT INTO project_memberships (project_id, user_id, role, created_by)
         VALUES ($1, $2, $3, $4)
         RETURNING project_id, user_id, role, created_at`,
        [parsedId.data, target.rows[0].id, body.data.role, user.id],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
         VALUES ($1, $2, 'project.member.add', 'user', $3, jsonb_build_object('role', $4))`,
        [user.id, parsedId.data, target.rows[0].id, body.data.role],
      );
      await client.query("COMMIT");
      response.status(201).json({ membership: inserted.rows[0] });
    } catch (error) {
      await client.query("ROLLBACK");
      if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
        response.status(409).json({ error: { code: "MEMBER_ALREADY_EXISTS", message: "This user is already a project member." } });
        return;
      }
      throw error;
    } finally {
      client.release();
    }
  });

  router.patch("/:projectId/members/:userId", async (request, response) => {
    const parsedId = z.string().uuid().safeParse(request.params["projectId"]);
    const parsedUserId = z.string().uuid().safeParse(request.params["userId"]);
    const body = z.object({ role: z.enum(["project_admin", "developer", "read_only"]) }).strict().safeParse(request.body);
    if (!parsedId.success || !parsedUserId.success) {
      response.status(400).json({ error: { code: "INVALID_ID", message: "A project or user ID is invalid." } });
      return;
    }
    if (!body.success) {
      response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Provide a valid project role." } });
      return;
    }
    const user = currentUser(response);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await client.query("SELECT id FROM projects WHERE id = $1 FOR UPDATE", [parsedId.data]);
      if (!project.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      const access = await client.query<{ role: string }>(
        "SELECT role FROM project_memberships WHERE project_id = $1 AND user_id = $2",
        [parsedId.data, user.id],
      );
      if (!user.is_platform_admin && !access.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      if (!user.is_platform_admin && access.rows[0]?.role !== "project_admin") {
        await client.query("ROLLBACK");
        response.status(403).json({ error: { code: "FORBIDDEN", message: "Project administrator permission is required." } });
        return;
      }
      const target = await client.query<{ role: string }>(
        "SELECT role FROM project_memberships WHERE project_id = $1 AND user_id = $2 FOR UPDATE",
        [parsedId.data, parsedUserId.data],
      );
      if (!target.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "MEMBER_NOT_FOUND", message: "The project member was not found." } });
        return;
      }
      if (target.rows[0].role === "project_admin" && body.data.role !== "project_admin") {
        const admins = await client.query<{ count: string }>(
          "SELECT count(*)::text AS count FROM project_memberships WHERE project_id = $1 AND role = 'project_admin'",
          [parsedId.data],
        );
        if (Number(admins.rows[0]?.count ?? "0") <= 1) {
          await client.query("ROLLBACK");
          response.status(409).json({ error: { code: "LAST_PROJECT_ADMIN", message: "A project must retain at least one project administrator." } });
          return;
        }
      }
      const updated = await client.query(
        `UPDATE project_memberships SET role = $3
          WHERE project_id = $1 AND user_id = $2
          RETURNING project_id, user_id, role, created_at`,
        [parsedId.data, parsedUserId.data, body.data.role],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
         VALUES ($1, $2, 'project.member.role_change', 'user', $3, jsonb_build_object('role', $4))`,
        [user.id, parsedId.data, parsedUserId.data, body.data.role],
      );
      await client.query("COMMIT");
      response.status(200).json({ membership: updated.rows[0] });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  });

  router.delete("/:projectId/members/:userId", async (request, response) => {
    const parsedId = z.string().uuid().safeParse(request.params["projectId"]);
    const parsedUserId = z.string().uuid().safeParse(request.params["userId"]);
    if (!parsedId.success || !parsedUserId.success) {
      response.status(400).json({ error: { code: "INVALID_ID", message: "A project or user ID is invalid." } });
      return;
    }
    const user = currentUser(response);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await client.query("SELECT id FROM projects WHERE id = $1 FOR UPDATE", [parsedId.data]);
      if (!project.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      const access = await client.query<{ role: string }>(
        "SELECT role FROM project_memberships WHERE project_id = $1 AND user_id = $2",
        [parsedId.data, user.id],
      );
      if (!user.is_platform_admin && !access.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "PROJECT_NOT_FOUND", message: "The project was not found." } });
        return;
      }
      if (!user.is_platform_admin && access.rows[0]?.role !== "project_admin") {
        await client.query("ROLLBACK");
        response.status(403).json({ error: { code: "FORBIDDEN", message: "Project administrator permission is required." } });
        return;
      }
      const target = await client.query<{ role: string }>(
        "SELECT role FROM project_memberships WHERE project_id = $1 AND user_id = $2 FOR UPDATE",
        [parsedId.data, parsedUserId.data],
      );
      if (!target.rows[0]) {
        await client.query("ROLLBACK");
        response.status(404).json({ error: { code: "MEMBER_NOT_FOUND", message: "The project member was not found." } });
        return;
      }
      if (target.rows[0].role === "project_admin") {
        const admins = await client.query<{ count: string }>(
          "SELECT count(*)::text AS count FROM project_memberships WHERE project_id = $1 AND role = 'project_admin'",
          [parsedId.data],
        );
        if (Number(admins.rows[0]?.count ?? "0") <= 1) {
          await client.query("ROLLBACK");
          response.status(409).json({ error: { code: "LAST_PROJECT_ADMIN", message: "A project must retain at least one project administrator." } });
          return;
        }
      }
      await client.query(
        "DELETE FROM project_memberships WHERE project_id = $1 AND user_id = $2",
        [parsedId.data, parsedUserId.data],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id)
         VALUES ($1, $2, 'project.member.remove', 'user', $3)`,
        [user.id, parsedId.data, parsedUserId.data],
      );
      await client.query("COMMIT");
      response.status(204).end();
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  });

  return router;
}
