import { describe, expect, it } from "vitest";
import request from "supertest";
import type { Pool } from "pg";
import { createApp } from "../src/app.js";
import { hashPassword } from "../src/auth/password.js";

describe("project routes", () => {
  it("requires authentication before listing projects", async () => {
    const pool = { async query() { return { rows: [] }; } } as unknown as Pool;
    const response = await request(createApp({ pool })).get("/api/projects");
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe("UNAUTHENTICATED");
  });

  it("creates a project and returns a project-admin membership", async () => {
    const userId = "00000000-0000-4000-8000-000000000001";
    const passwordHash = await hashPassword("correct horse battery staple");
    let activeTokenHash: Buffer | undefined;
    const user = {
      id: userId, email: "owner@example.com", display_name: "Owner",
      password_hash: passwordHash, status: "active", is_platform_admin: true,
    };
    const pool = {
      async query(sql: string, values: unknown[] = []) {
        if (sql.includes("FROM users WHERE email_normalized")) return { rows: [user] };
        if (sql.includes("INSERT INTO sessions")) {
          activeTokenHash = values[1] as Buffer;
          return { rows: [] };
        }
        if (sql.includes("FROM sessions s")) {
          const tokenHash = values[0] as Buffer;
          return activeTokenHash?.equals(tokenHash)
            ? { rows: [{ id: userId, email: user.email, display_name: user.display_name, is_platform_admin: true }] }
            : { rows: [] };
        }
        if (sql.includes("UPDATE sessions SET last_seen_at")) return { rows: [] };
        if (sql.includes("WITH new_project AS")) {
          return { rows: [{
            id: "00000000-0000-4000-8000-000000000002",
            name: values[0], slug: values[1], created_at: "2026-11-19T00:00:00.000Z",
            role: "project_admin",
          }] };
        }
        throw new Error("Unexpected SQL in project test");
      },
    } as unknown as Pool;

    const agent = request.agent(createApp({ pool }));
    const login = await agent.post("/api/auth/login").send({
      email: "owner@example.com", password: "correct horse battery staple",
    });
    expect(login.status).toBe(200);

    const created = await agent.post("/api/projects").send({ name: "Production Database" });
    expect(created.status).toBe(201);
    expect(created.body.project).toMatchObject({
      name: "Production Database", slug: "production-database", role: "project_admin",
    });
  });

  it("rejects invalid project input", async () => {
    const userId = "00000000-0000-4000-8000-000000000001";
    const passwordHash = await hashPassword("correct horse battery staple");
    let activeTokenHash: Buffer | undefined;
    const pool = {
      async query(sql: string, values: unknown[] = []) {
        if (sql.includes("FROM users WHERE email_normalized")) {
          return { rows: [{
            id: userId, email: "owner@example.com", display_name: "Owner",
            password_hash: passwordHash, status: "active", is_platform_admin: true,
          }] };
        }
        if (sql.includes("INSERT INTO sessions")) {
          activeTokenHash = values[1] as Buffer;
          return { rows: [] };
        }
        if (sql.includes("INSERT INTO audit_events")) return { rows: [] };
        if (sql.includes("FROM sessions s")) {
          const tokenHash = values[0] as Buffer;
          return activeTokenHash?.equals(tokenHash)
            ? { rows: [{ id: userId, email: "owner@example.com", display_name: "Owner", is_platform_admin: true }] }
            : { rows: [] };
        }
        if (sql.includes("UPDATE sessions SET last_seen_at")) return { rows: [] };
        throw new Error("Unexpected SQL in project validation test");
      },
    } as unknown as Pool;

    const agent = request.agent(createApp({ pool }));
    await agent.post("/api/auth/login").send({ email: "owner@example.com", password: "correct horse battery staple" });
    const response = await agent.post("/api/projects").send({ name: "", slug: "not valid" });
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("VALIDATION_ERROR");
  });
});
