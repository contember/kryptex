import { createExecutionContext } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, test } from "vitest";
import { checkWorkerEnvironment, type WorkerSecurityEnvironment } from "./env.js";

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function validEnvironment(): WorkerSecurityEnvironment {
  return {
    CAPABILITY_ACTIVE_KEY_ID: "dev-v1",
    CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}"}`,
    EXPECTED_ORIGIN: "https://secrets.example",
    PERMIT_ISSUANCE_KEY: key,
    RATE_LIMIT_KEY: key,
    TURNSTILE_EXPECTED_ACTION: "create_permit",
    TURNSTILE_EXPECTED_HOSTNAME: "secrets.example",
    TURNSTILE_SECRET_KEY: "turnstile-secret"
  };
}

describe("Worker environment validation", () => {
  test("exposes the typed integration Worker and enforces the origin gate", async () => {
    const context = createExecutionContext();
    context.waitUntil(Promise.resolve());
    const response = await exports.default.fetch(new Request("https://kryptex.invalid/api/v1/probe", { method: "POST" }));
    expect(response.status).toBe(403);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toEqual({ error: "forbidden" });
  });

  test("accepts the complete security environment", () => {
    const checked = checkWorkerEnvironment(validEnvironment());
    expect(checked.activeCapabilityKeyId).toBe("dev-v1");
    expect(checked.activeCapabilityKey).toHaveLength(32);
    expect(checked.permitIssuanceKey).toHaveLength(32);
    expect(checked.rateLimitKey).toHaveLength(32);
  });

  test("rejects a missing active key and malformed secrets", () => {
    expect(() =>
      checkWorkerEnvironment({
        ...validEnvironment(),
        CAPABILITY_ACTIVE_KEY_ID: "missing"
      })
    ).toThrow();
    expect(() =>
      checkWorkerEnvironment({
        ...validEnvironment(),
        RATE_LIMIT_KEY: `${key.slice(0, -1)}B`
      })
    ).toThrow();
  });

  test("rejects duplicate key IDs and non-origin configuration", () => {
    expect(() =>
      checkWorkerEnvironment({
        ...validEnvironment(),
        CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}","dev-v1":"${key}"}`
      })
    ).toThrow(/duplicate/u);
    expect(() =>
      checkWorkerEnvironment({
        ...validEnvironment(),
        EXPECTED_ORIGIN: "https://secrets.example/path"
      })
    ).toThrow();
  });
});
