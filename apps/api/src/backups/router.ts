import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Pool } from "pg";
import { resolveSession } from "../auth/router.js";
import { BackupRequestError, getProjectBackup, listProjectBackups, requestBackup } from "./repository.js";

function sendBackupError(error: unknown, response: Response, next: NextFunction): void {
  if (error instanceof BackupRequestError) {
    const status = error.code === "PROJECT_NOT_FOUND" || error.code === "CONNECTION_NOT_FOUND" || error.code === "DATABASE_NOT_FOUND" || error.code === "BACKUP_NOT_FOUND" ? 404
      : error.code === "FORBIDDEN" ? 403
      : error.code === "CONNECTION_DISABLED" || error.code === "DATABASE_NOT_READY" || error.code === "BACKUP_OPERATION_ACTIVE" ? 409 : 400;
    response.status(status).json({ error: { code: error.code, message: error.message } });
    return;
  }
  next(error);
}

export function createBackupsRouter(pool: Pool): Router {
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
      response.locals["backupCaller"] = { userId: user.id, isPlatformAdmin: user.is_platform_admin };
      next();
    } catch (error) { next(error); }
  });

  router.get("/:projectId/backups", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const query = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }).strict().safeParse(request.query);
    if (!projectId.success || !query.success) {
      response.status(400).json({ error: { code: "INVALID_QUERY", message: "Project ID or backup list limit is invalid." } });
      return;
    }
    try {
      const backups = await listProjectBackups(
        pool,
        response.locals["backupCaller"] as { userId: string; isPlatformAdmin: boolean },
        projectId.data,
        query.data.limit,
      );
      response.status(200).json({ backups });
    } catch (error) { sendBackupError(error, response, next); }
  });

  router.post("/:projectId/backups", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const body = z.object({
      databaseId: z.string().uuid(),
      name: z.string().trim().min(1).max(100),
    }).strict().safeParse(request.body);
    if (!projectId.success || !body.success) {
      response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Provide a valid managed database ID and backup name." } });
      return;
    }
    try {
      const backup = await requestBackup(pool, {
        caller: response.locals["backupCaller"] as { userId: string; isPlatformAdmin: boolean },
        projectId: projectId.data,
        databaseId: body.data.databaseId,
        name: body.data.name,
      });
      response.status(202).json({ backup });
    } catch (error) { sendBackupError(error, response, next); }
  });

  router.get("/:projectId/backups/:backupId", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const backupId = z.string().uuid().safeParse(request.params["backupId"]);
    if (!projectId.success || !backupId.success) {
      response.status(400).json({ error: { code: "INVALID_ID", message: "A project or backup ID is invalid." } });
      return;
    }
    try {
      const backup = await getProjectBackup(
        pool,
        response.locals["backupCaller"] as { userId: string; isPlatformAdmin: boolean },
        projectId.data,
        backupId.data,
      );
      if (!backup) {
        response.status(404).json({ error: { code: "BACKUP_NOT_FOUND", message: "The backup was not found." } });
        return;
      }
      response.status(200).json({ backup });
    } catch (error) { sendBackupError(error, response, next); }
  });

  return router;
}
