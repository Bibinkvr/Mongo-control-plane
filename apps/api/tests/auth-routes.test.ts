import { describe, expect, it } from "vitest";
import request from "supertest";
import type { Pool } from "pg";
import { createApp } from "../src/app.js";
import { hashPassword } from "../src/auth/password.js";

describe("authentication routes", () => {
  it("supports login, session identity, logout, and session revocation", async () => {
    const userId = "00000000-0000-4000-8000-000000000001";
    const passwordHash = await hashPassword("correct horse battery staple");
    let activeTokenHash: Buffer | undefined;
    let revoked = false;
    const user = {
      id: userId,
      email: "admin@example.com",
      display_name: "Admin",
      password_hash: passwordHash,
      status: "active",
      is_platform_admin: true,
    };

    const pool = {
      async query(sql: string, values: unknown[] = []) {
        if (sql.includes("FROM users WHERE email_normalized")) return { rows: [user] };
        if (sql.includes("INSERT INTO sessions")) {
          activeTokenHash = values[1] as Buffer;
          return { rows: [] };
        }
        if (sql.includes("UPDATE sessions SET revoked_at")) {
          const tokenHash = values[0] as Buffer;
          if (!revoked && activeTokenHash?.equals(tokenHash)) {
            revoked = true;
            return { rows: [{ user_id: userId }] };
          }
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO audit_events")) return { rows: [] };
        if (sql.includes("FROM sessions s")) {
          const tokenHash = values[0] as Buffer;
          if (!revoked && activeTokenHash?.equals(tokenHash)) {
            return { rows: [{ id: userId, email: user.email, display_name: user.display_name, is_platform_admin: true }] };
          }
          return { rows: [] };
        }
        if (sql.includes("UPDATE sessions SET last_seen_at")) return { rows: [] };
        throw new Error("Unexpected SQL in auth test");
      },
    } as unknown as Pool;

    const app = createApp({ pool });
    const agent = request.agent(app);

    const login = await agent.post("/api/auth/login").send({
      email: "ADMIN@example.com",
      password: "correct horse battery staple",
    });
    expect(login.status).toBe(200);
    expect(login.body.user).toMatchObject({ id: userId, email: "admin@example.com", isPlatformAdmin: true });
    expect(login.headers["set-cookie"][0]).toContain("HttpOnly");
    expect(login.headers["set-cookie"][0]).toContain("SameSite=Lax");

    const me = await agent.get("/api/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe("admin@example.com");

    const logout = await agent.post("/api/auth/logout");
    expect(logout.status).toBe(204);
    expect(logout.headers["set-cookie"][0]).toContain("Max-Age=0");

    const afterLogout = await agent.get("/api/auth/me");
    expect(afterLogout.status).toBe(401);
  });

  it("returns a generic error for invalid credentials", async () => {
    const pool = {
      async query() { return { rows: [] }; },
    } as unknown as Pool;
    const response = await request(createApp({ pool })).post("/api/auth/login")
      .send({ email: "missing@example.com", password: "some password" });
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("INVALID_CREDENTIALS");
    expect(JSON.stringify(response.body)).not.toContain("missing@example.com");
  });

  it("rejects malformed login payloads", async () => {
    const pool = { async query() { return { rows: [] }; } } as unknown as Pool;
    const response = await request(createApp({ pool })).post("/api/auth/login")
      .send({ email: "not-an-email", password: "" });
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("VALIDATION_ERROR");
  });
});
