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
  // Express/body-parser errors carry a stable type and status. Do not expose
  // parser internals or arbitrary exception messages to clients.
  if (
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    error.type === "entity.parse.failed"
  ) {
    response.status(400).json({
      error: {
        code: "INVALID_JSON",
        message: "The request body must contain valid JSON.",
      },
    });
    return;
  }

  if (
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    error.type === "entity.too.large"
  ) {
    response.status(413).json({
      error: {
        code: "PAYLOAD_TOO_LARGE",
        message: "The request body exceeds the permitted size.",
      },
    });
    return;
  }

  response.status(500).json({
    error: {
      code: "INTERNAL_SERVER_ERROR",
      message: "An unexpected error occurred.",
    },
  });

  // Structured, secret-redacting logging will be added before production use.
  if (process.env.NODE_ENV !== "test") {
    process.stderr.write("Unhandled API error\n");
  }
};

export function createApp() {
  const app = express();

  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "1mb", strict: true }));

  app.get("/health/live", (_request, response) => {
    response.status(200).json({ status: "ok" });
  });

  // Process-only readiness. Dependency checks will be registered when
  // PostgreSQL and Redis adapters are implemented.
  app.get("/health/ready", (_request, response) => {
    response.status(200).json({ status: "ready", checks: {} });
  });

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
