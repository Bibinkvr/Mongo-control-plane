import { Router, type Request, type Response } from "express";
import { z } from "zod";
import type { Pool } from "pg";
import { hashSessionToken, createSessionToken, readSessionCookie } from "./session.js";
import { verifyPassword } from "./password.js";

const loginSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(1024),
}).strict();

const COOKIE_NAME = "mcp_session";
const SESSION_DAYS = 7;

type AuthenticatedUser = {
  id: string;
  email: string;
  display_name: string;
  is_platform_admin: boolean;
};

function setSessionCookie(response: Response, token: string, secure: boolean): void {
  const attributes = [
    `${COOKIE_NAME}=${token}`,
    "Path=/api/auth",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`,
  ];
  if (secure) attributes.push("Secure");
  response.append("Set-Cookie", attributes.join("; "));
}

function clearSessionCookie(response: Response, secure: boolean): void {
  const attributes = [`${COOKIE_NAME}=`, "Path=/api/auth", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (secure) attributes.push("Secure");
  response.append("Set-Cookie", attributes.join("; "));
}

export async function resolveSession(pool: Pool, request: Request): Promise<AuthenticatedUser | null> {
  const token = readSessionCookie(request.headers.cookie, COOKIE_NAME);
  if (!token) return null;

  const result = await pool.query<AuthenticatedUser>(
    `SELECT u.id, u.email_normalized AS email, u.display_name, u.is_platform_admin
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1
        AND s.revoked_at IS NULL
        AND s.expires_at > now()
        AND u.status = 'active'
      LIMIT 1`,
    [hashSessionToken(token)],
  );

  if (!result.rows[0]) return null;

  // last_seen_at is updated at most once every five minutes to avoid a write
  // for every API request.
  await pool.query(
    `UPDATE sessions SET last_seen_at = now()
      WHERE token_hash = $1 AND last_seen_at < now() - interval '5 minutes'`,
    [hashSessionToken(token)],
  );
  return result.rows[0];
}

export function createAuthRouter(pool: Pool, secureCookies: boolean): Router {
  const router = Router();

  router.post("/login", async (request, response) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ error: { code: "VALIDATION_ERROR", message: "Enter a valid email and password." } });
      return;
    }

    const email = parsed.data.email.toLowerCase();
    const result = await pool.query<{
      id: string; email: string; display_name: string; password_hash: string;
      status: string; is_platform_admin: boolean;
    }>(
      `SELECT id, email_normalized AS email, display_name, password_hash, status, is_platform_admin
         FROM users WHERE email_normalized = $1 LIMIT 1`,
      [email],
    );
    const user = result.rows[0];

    if (!user || user.status !== "active" || !(await verifyPassword(parsed.data.password, user.password_hash))) {
      response.status(401).json({ error: { code: "INVALID_CREDENTIALS", message: "Email or password is incorrect." } });
      return;
    }

    const token = createSessionToken();
    const tokenHash = hashSessionToken(token);
    await pool.query(
      `WITH created_session AS (
         INSERT INTO sessions (user_id, token_hash, expires_at)
         VALUES ($1, $2, now() + interval '7 days')
         RETURNING user_id
       )
       INSERT INTO audit_events (actor_user_id, action, target_type, target_id, metadata)
       SELECT user_id, 'auth.login', 'session', NULL, jsonb_build_object('method', 'password')
       FROM created_session`,
      [user.id, tokenHash],
    );

    setSessionCookie(response, token, secureCookies);
    response.status(200).json({
      user: { id: user.id, email: user.email, displayName: user.display_name, isPlatformAdmin: user.is_platform_admin },
    });
  });

  router.post("/logout", async (request, response) => {
    const token = readSessionCookie(request.headers.cookie, COOKIE_NAME);
    if (token) {
      const tokenHash = hashSessionToken(token);
      await pool.query(
        `WITH revoked_session AS (
           UPDATE sessions SET revoked_at = now()
            WHERE token_hash = $1 AND revoked_at IS NULL
            RETURNING user_id
         )
         INSERT INTO audit_events (actor_user_id, action, target_type, metadata)
         SELECT user_id, 'auth.logout', 'session', jsonb_build_object('method', 'password')
         FROM revoked_session`,
        [tokenHash],
      );
    }
    clearSessionCookie(response, secureCookies);
    response.status(204).end();
  });

  router.get("/me", async (request, response) => {
    const user = await resolveSession(pool, request);
    if (!user) {
      response.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Authentication is required." } });
      return;
    }
    response.status(200).json({
      user: { id: user.id, email: user.email, displayName: user.display_name, isPlatformAdmin: user.is_platform_admin },
    });
  });

  return router;
}
