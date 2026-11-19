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

  return router;
}
