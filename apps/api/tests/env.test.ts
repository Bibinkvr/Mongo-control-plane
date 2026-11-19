import { describe, expect, it } from "vitest";
import { parseEnv } from "../src/config/env.js";

describe("environment validation", () => {
  it("applies safe development defaults", () => {
    expect(parseEnv({})).toMatchObject({
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      PORT: 5000,
      LOG_LEVEL: "info",
    });
  });

  it("rejects invalid ports", () => {
    expect(() => parseEnv({ PORT: "70000" })).toThrow(/Invalid environment configuration/);
  });

  it("rejects unsupported runtime environments", () => {
    expect(() => parseEnv({ NODE_ENV: "staging" })).toThrow(/Invalid environment configuration/);
  });
});
