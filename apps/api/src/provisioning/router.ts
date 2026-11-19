import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Pool } from "pg";
import { resolveSession } from "../auth/router.js";
import type { EncryptionKeyring } from "../connections/crypto.js";
import { createDatabaseProvisioningRequest, listProjectDatabases, requestDatabaseDeletion, ProvisioningRequestError } from "./repository.js";
import { DatabaseCredentialError, revealDatabaseConnectionUri, rotateDatabaseCredentialKey } from "./credentials.js";

function sendProvisioningError(error: unknown, response: Response, next: NextFunction): void {
  if (error instanceof ProvisioningRequestError || error instanceof DatabaseCredentialError) {
    const status = error.code === "PROJECT_NOT_FOUND" || error.code === "CONNECTION_NOT_FOUND" || error.code === "DATABASE_NOT_FOUND" ? 404
      : error.code === "FORBIDDEN" ? 403
      : error.code === "RESOURCE_NAME_TAKEN" || error.code === "DATABASE_OPERATION_ACTIVE" || error.code === "DATABASE_NOT_READY" ? 409
      : error.code === "CONNECTION_DISABLED" ? 409 : 400;
    response.status(status).json({ error: { code: error.code, message: error.message } });
    return;
  }
  next(error);
}

export function createDatabasesRouter(pool: Pool, keyring: EncryptionKeyring): Router {
  const router = Router();
  router.use((_request, response, next) => { response.setHeader("Cache-Control", "no-store"); next(); });
  router.use(async (request: Request, response: Response, next: NextFunction) => {
    try {
      const user = await resolveSession(pool, request);
      if (!user) { response.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Authentication is required." } }); return; }
      response.locals["databaseCaller"] = { userId: user.id, isPlatformAdmin: user.is_platform_admin };
      next();
    } catch (error) { next(error); }
  });

  router.get("/:projectId/databases", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    if (!projectId.success) { response.status(400).json({ error: { code: "INVALID_PROJECT_ID", message: "The project ID is invalid." } }); return; }
    try {
      const resources = await listProjectDatabases(pool, response.locals["databaseCaller"] as { userId: string; isPlatformAdmin: boolean }, projectId.data);
      response.status(200).json({ databases: resources });
    } catch (error) { sendProvisioningError(error, response, next); }
  });

  router.post("/:projectId/databases", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const body = z.object({ connectionId: z.string().uuid(), name: z.string().trim().min(1).max(100) }).strict().safeParse(request.body);
    if (!projectId.success) { response.status(400).json({ error: { code: "INVALID_PROJECT_ID", message: "The project ID is invalid." } }); return; }
    if (!body.success) { response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Provide a valid connection ID and database name." } }); return; }
    try {
      const database = await createDatabaseProvisioningRequest(pool, keyring, {
        caller: response.locals["databaseCaller"] as { userId: string; isPlatformAdmin: boolean },
        projectId: projectId.data, connectionId: body.data.connectionId, name: body.data.name,
      });
      response.status(202).json({ database });
    } catch (error) { sendProvisioningError(error, response, next); }
  });



  router.delete("/:projectId/databases/:databaseId", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const databaseId = z.string().uuid().safeParse(request.params["databaseId"]);
    const body = z.object({ confirmDatabaseName: z.string().min(1).max(100) }).strict().safeParse(request.body);
    if (!projectId.success || !databaseId.success) {
      response.status(400).json({ error: { code: "INVALID_ID", message: "A project or database ID is invalid." } });
      return;
    }
    if (!body.success) {
      response.status(400).json({ error: { code: "CONFIRMATION_REQUIRED", message: "Confirm the exact database name before deletion." } });
      return;
    }
    try {
      const result = await requestDatabaseDeletion(pool, {
        caller: response.locals["databaseCaller"] as { userId: string; isPlatformAdmin: boolean },
        projectId: projectId.data,
        databaseId: databaseId.data,
        confirmDatabaseName: body.data.confirmDatabaseName,
      });
      response.status(202).json({ database: result });
    } catch (error) { sendProvisioningError(error, response, next); }
  });

  router.post("/:projectId/databases/:databaseId/rotate-key", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const databaseId = z.string().uuid().safeParse(request.params["databaseId"]);
    if (!projectId.success || !databaseId.success) {
      response.status(400).json({ error: { code: "INVALID_ID", message: "A project or database ID is invalid." } });
      return;
    }
    try {
      const result = await rotateDatabaseCredentialKey(pool, keyring, {
        caller: response.locals["databaseCaller"] as { userId: string; isPlatformAdmin: boolean },
        projectId: projectId.data,
        databaseId: databaseId.data,
      });
      response.status(200).json(result);
    } catch (error) { sendProvisioningError(error, response, next); }
  });

  router.post("/:projectId/databases/:databaseId/credentials", async (request, response, next) => {
    const projectId = z.string().uuid().safeParse(request.params["projectId"]);
    const databaseId = z.string().uuid().safeParse(request.params["databaseId"]);
    if (!projectId.success || !databaseId.success) {
      response.status(400).json({ error: { code: "INVALID_ID", message: "A project or database ID is invalid." } });
      return;
    }
    try {
      const uri = await revealDatabaseConnectionUri(pool, keyring, {
        caller: response.locals["databaseCaller"] as { userId: string; isPlatformAdmin: boolean },
        projectId: projectId.data,
        databaseId: databaseId.data,
      });
      response.status(200).json({ uri });
    } catch (error) { sendProvisioningError(error, response, next); }
  });
  return router;
}
