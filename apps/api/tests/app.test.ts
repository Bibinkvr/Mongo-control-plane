import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";

describe("API foundation", () => {
  const app = createApp();

  it("reports liveness", async () => {
    const response = await request(app).get("/health/live");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("reports process readiness without claiming dependency checks", async () => {
    const response = await request(app).get("/health/ready");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ready", checks: {} });
  });

  it("returns a consistent JSON 404 response", async () => {
    const response = await request(app).get("/does-not-exist");

    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe("NOT_FOUND");
  });

  it("rejects malformed JSON", async () => {
    const response = await request(app)
      .post("/test")
      .set("content-type", "application/json")
      .send("{invalid");

    expect(response.status).toBe(400);
  });
});
