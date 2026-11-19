import express, { type ErrorRequestHandler, type RequestHandler } from "express";
import helmet from "helmet";

const notFoundHandler: RequestHandler = (_request, response) => {
  response.status(404).json({
    error: {
      code: "NOT_FOUND",
      message: "The requested resource was not found.",
    },
  });
};

const errorHandler: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
  // Never return internal exception messages or stack traces to API clients.
  response.status(500).json({
    error: {
      code: "INTERNAL_SERVER_ERROR",
      message: "An unexpected error occurred.",
    },
  });
  // Replace with structured, secret-redacting logging before production release.
  if (process.env.NODE_ENV !== "test") {
    process.stderr.write("Unhandled API error\n");
  }
  void error;
};

export function createApp() {
  const app = express();

  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "1mb", strict: true }));

  app.get("/health/live", (_request, response) => {
    response.status(200).json({ status: "ok" });
  });

  // This initial endpoint reports process readiness only. Dependency-aware
  // readiness will be introduced when PostgreSQL and Redis adapters exist.
  app.get("/health/ready", (_request, response) => {
    response.status(200).json({ status: "ready", checks: {} });
  });

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
