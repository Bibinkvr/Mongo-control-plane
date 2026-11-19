import express, { type ErrorRequestHandler, type RequestHandler } from "express";
import helmet from "helmet";
import type { Pool } from "pg";
import { createAuthRouter } from "./auth/router.js";
import { checkPostgres } from "./db/health.js";
import { createProjectsRouter } from "./projects/router.js";
import { createConnectionsRouter } from "./connections/router.js";
import { createDatabasesRouter } from "./provisioning/router.js";
import { createWorkspaceRouter } from "./workspace/router.js";
import type { WorkspacePolicy } from "./workspace/service.js";
import type { EncryptionKeyring } from "./connections/crypto.js";

const notFoundHandler: RequestHandler = (_request, response) => {
  response.status(404).json({ error: { code: "NOT_FOUND", message: "The requested resource was not found." } });
};

const errorHandler: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
  if (typeof error === "object" && error !== null && "type" in error && error.type === "entity.parse.failed") {
    response.status(400).json({ error: { code: "INVALID_JSON", message: "The request body must contain valid JSON." } });
    return;
  }
  if (typeof error === "object" && error !== null && "type" in error && error.type === "entity.too.large") {
    response.status(413).json({ error: { code: "PAYLOAD_TOO_LARGE", message: "The request body exceeds the permitted size." } });
    return;
  }
  response.status(500).json({ error: { code: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred." } });
  if (process.env["NODE_ENV"] !== "test") process.stderr.write("Unhandled API error\n");
};

export type AppOptions = {
  pool?: Pool | undefined;
  secureCookies?: boolean;
  encryptionKeyring?: EncryptionKeyring;
  mongoNetworkPolicy?: WorkspacePolicy;
};

export function createApp(options: AppOptions = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "1mb", strict: true }));

  app.get("/health/live", (_request, response) => response.status(200).json({ status: "ok" }));

  app.get("/health/ready", async (_request, response) => {
    if (!options.pool) {
      response.status(503).json({ status: "not_ready", checks: { postgres: "not_configured" } });
      return;
    }
    const healthy = await checkPostgres(options.pool);
    response.status(healthy ? 200 : 503).json({
      status: healthy ? "ready" : "not_ready",
      checks: { postgres: healthy ? "ok" : "unavailable" },
    });
  });

  if (options.pool) {
    app.use("/api/auth", createAuthRouter(options.pool, options.secureCookies ?? false));
    app.use("/api/projects", createProjectsRouter(options.pool));
    if (options.encryptionKeyring) {
      app.use("/api/projects", createConnectionsRouter(options.pool, options.encryptionKeyring));
      app.use("/api/projects", createDatabasesRouter(options.pool, options.encryptionKeyring));
      app.use("/api/projects", createWorkspaceRouter(options.pool, options.encryptionKeyring, options.mongoNetworkPolicy ?? {}));
    } else {
      app.use("/api/projects/:projectId/connections", (_request, response) => {
        response.status(503).json({ error: { code: "ENCRYPTION_UNAVAILABLE", message: "Connection management is temporarily unavailable." } });
      });
      app.use("/api/projects/:projectId/databases", (_request, response) => {
        response.status(503).json({ error: { code: "ENCRYPTION_UNAVAILABLE", message: "Database provisioning is temporarily unavailable." } });
      });
    }
  } else {
    app.use("/api/auth", (_request, response) => {
      response.status(503).json({ error: { code: "DATABASE_UNAVAILABLE", message: "Authentication is temporarily unavailable." } });
    });
    app.use("/api/projects", (_request, response) => {
      response.status(503).json({ error: { code: "DATABASE_UNAVAILABLE", message: "Project management is temporarily unavailable." } });
    });
  }

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
