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

  it("returns a safe 400 response for malformed JSON", async () => {
    const response = await request(app)
      .post("/test")
      .set("content-type", "application/json")
      .send("{invalid");

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("INVALID_JSON");
    expect(response.body.error.message).not.toContain("Unexpected");
  });

  it("rejects request bodies larger than the configured limit", async () => {
    const oversized = JSON.stringify({ value: "x".repeat(1_100_000) });
    const response = await request(app)
      .post("/test")
      .set("content-type", "application/json")
      .send(oversized);

    expect(response.status).toBe(413);
    expect(response.body.error.code).toBe("PAYLOAD_TOO_LARGE");
  });
});
