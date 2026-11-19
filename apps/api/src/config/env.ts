import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().trim().min(1).default("127.0.0.1"),
  PORT: z.coerce.number().int().min(1).max(65_535).default(5000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug"]).default("info"),
  DATABASE_URL: z.string().trim().url().optional(),
  CONNECTION_ENCRYPTION_KEYS: z.string().optional(),
  CONNECTION_ENCRYPTION_CURRENT_VERSION: z.string().optional(),
  MONGODB_ALLOW_PRIVATE_NETWORKS: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  MONGODB_ALLOW_LOOPBACK: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  BACKUP_WORKER_EGRESS_ISOLATED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  MONGODUMP_PATH: z.string().trim().min(1).optional(),
  BACKUP_STORAGE_ROOT: z.string().trim().min(1).optional(),
  BACKUP_MAX_BYTES: z.coerce.number().int().min(1).max(20 * 1024 * 1024 * 1024).default(20 * 1024 * 1024 * 1024),
  BACKUP_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(86_400_000).default(6 * 60 * 60 * 1000),
}).superRefine((value, context) => {
  if (value.NODE_ENV === "production" && !value.DATABASE_URL) {
    context.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "is required in production" });
  }
  if (value.DATABASE_URL && !/^postgres(ql)?:\/\//i.test(value.DATABASE_URL)) {
    context.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "must use the PostgreSQL protocol" });
  }
  const hasKeys = Boolean(value.CONNECTION_ENCRYPTION_KEYS);
  const hasVersion = Boolean(value.CONNECTION_ENCRYPTION_CURRENT_VERSION);
  if (hasKeys !== hasVersion) {
    context.addIssue({ code: "custom", path: ["CONNECTION_ENCRYPTION_KEYS"], message: "keyring and current version must be configured together" });
  }
  if (value.NODE_ENV === "production" && value.MONGODB_ALLOW_LOOPBACK) {
    context.addIssue({ code: "custom", path: ["MONGODB_ALLOW_LOOPBACK"], message: "must be false in production" });
  }
  if (value.NODE_ENV === "production" && !hasKeys) {
    context.addIssue({ code: "custom", path: ["CONNECTION_ENCRYPTION_KEYS"], message: "is required in production" });
  }
});

export type AppEnv = z.infer<typeof envSchema>;

export function parseEnv(input: NodeJS.ProcessEnv): AppEnv {
  const parsed = envSchema.safeParse(input);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "environment"}: ${issue.message}`)
      .join("; ");
    throw new Error(`Invalid environment configuration: ${details}`);
  }
  return parsed.data;
}
