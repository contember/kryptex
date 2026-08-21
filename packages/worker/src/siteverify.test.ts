import { afterEach, describe, expect, test } from "vitest";
import { env } from "cloudflare:workers";
import { reset } from "cloudflare:test";
import { checkWorkerEnvironment, LOCAL_TURNSTILE_DUMMY_SECRET, type WorkerEnv, type WorkerSecurityEnvironment } from "./env.js";
import { handleApiRequest, LOCAL_TURNSTILE_DUMMY_TOKEN, verifyTurnstile } from "./index.js";

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ORIGIN = "http://localhost:5173";

afterEach(async () => {
  await reset();
});

function checkedEnvironment() {
  const environment: WorkerSecurityEnvironment = {
    CAPABILITY_ACTIVE_KEY_ID: "dev-v1",
    CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}"}`,
    EXPECTED_ORIGIN: "https://secrets.example",
    PERMIT_ISSUANCE_KEY: key,
    RATE_LIMIT_KEY: key,
    TURNSTILE_EXPECTED_ACTION: "create_permit",
    TURNSTILE_EXPECTED_HOSTNAME: "secrets.example",
    TURNSTILE_SECRET_KEY: "turnstile-secret"
  };
  return checkWorkerEnvironment(environment);
}

function localCheckedEnvironment() {
  return checkWorkerEnvironment({
    CAPABILITY_ACTIVE_KEY_ID: "dev-v1",
    CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}"}`,
    EXPECTED_ORIGIN: ORIGIN,
    PERMIT_ISSUANCE_KEY: key,
    RATE_LIMIT_KEY: key,
    TURNSTILE_EXPECTED_ACTION: "create_permit",
    TURNSTILE_EXPECTED_HOSTNAME: "localhost",
    TURNSTILE_SECRET_KEY: LOCAL_TURNSTILE_DUMMY_SECRET
  });
}

function workerEnvironment(): WorkerEnv {
  return {
    ASSETS: env.ASSETS,
    CAPABILITY_ACTIVE_KEY_ID: env.CAPABILITY_ACTIVE_KEY_ID,
    CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}"}`,
    CIPHERTEXT: env.CIPHERTEXT,
    CREATE_PERMIT_OBJECTS: env.CREATE_PERMIT_OBJECTS,
    EDGE_RATE_LIMITER: env.EDGE_RATE_LIMITER,
    EXPECTED_ORIGIN: env.EXPECTED_ORIGIN,
    LOCATOR_RATE_LIMITER: env.LOCATOR_RATE_LIMITER,
    PERMIT_ISSUANCE_KEY: key,
    RATE_LIMIT_KEY: key,
    REQUEST_OBJECTS: env.REQUEST_OBJECTS,
    SEND_OBJECTS: env.SEND_OBJECTS,
    TURNSTILE_EXPECTED_ACTION: env.TURNSTILE_EXPECTED_ACTION,
    TURNSTILE_EXPECTED_HOSTNAME: env.TURNSTILE_EXPECTED_HOSTNAME,
    TURNSTILE_SECRET_KEY: "test-turnstile-secret"
  };
}

function localWorkerEnvironment(): WorkerEnv {
  return {
    ...workerEnvironment(),
    TURNSTILE_SECRET_KEY: LOCAL_TURNSTILE_DUMMY_SECRET
  };
}

describe("Turnstile Siteverify", () => {
  test("accepts only the exact local dummy token without outbound Siteverify", async () => {
    let fetchCalled = false;
    const siteverifyFetch: typeof fetch = () => {
      fetchCalled = true;
      return Promise.reject(new Error("must not call Siteverify"));
    };
    const accepted = await verifyTurnstile(
      localCheckedEnvironment(),
      "00000000-0000-4000-8000-000000000010",
      LOCAL_TURNSTILE_DUMMY_TOKEN,
      siteverifyFetch
    );
    const rejected = await verifyTurnstile(
      localCheckedEnvironment(),
      "00000000-0000-4000-8000-000000000011",
      "wrong-token",
      siteverifyFetch
    );
    expect(accepted.kind).toBe("accepted");
    expect(accepted.kind === "accepted" ? accepted.permitExpiresAt : 0).toBeGreaterThan(Math.floor(Date.now() / 1_000));
    expect(rejected).toEqual({ kind: "failed" });
    expect(fetchCalled).toBe(false);
  });

  test("creates a public permit for the exact local dummy token and rejects another token", async () => {
    let fetchCalled = false;
    const siteverifyFetch: typeof fetch = () => {
      fetchCalled = true;
      return Promise.reject(new Error("must not call Siteverify"));
    };
    const request = (requestId: string, turnstileResponse: string) => new Request(`${ORIGIN}/api/v2/create-permits`, {
      body: JSON.stringify({ requestId, turnstileResponse }),
      headers: { "Content-Type": "application/json", Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      method: "POST"
    });
    const accepted = await handleApiRequest(
      request("00000000-0000-4000-8000-000000000012", LOCAL_TURNSTILE_DUMMY_TOKEN),
      localWorkerEnvironment(),
      siteverifyFetch
    );
    const rejected = await handleApiRequest(
      request("00000000-0000-4000-8000-000000000013", "wrong-token"),
      localWorkerEnvironment(),
      siteverifyFetch
    );
    expect(accepted.status).toBe(200);
    expect(accepted.headers.get("Set-Cookie")).toContain("kx_create_v2=v2.");
    expect(accepted.headers.get("Set-Cookie")).toContain("Max-Age=1800");
    const acceptedBody = await accepted.json<{ permitExpiresAt: number; serverTime: number }>();
    expect(acceptedBody.permitExpiresAt - acceptedBody.serverTime).toBe(1800);
    expect(rejected.status).toBe(403);
    expect(await rejected.json()).toEqual({ error: "gate_failed" });
    expect(fetchCalled).toBe(false);
  });

  test("rejects the dummy secret outside an exact localhost environment", () => {
    const base: WorkerSecurityEnvironment = {
      CAPABILITY_ACTIVE_KEY_ID: "dev-v1",
      CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}"}`,
      EXPECTED_ORIGIN: "https://secrets.example",
      PERMIT_ISSUANCE_KEY: key,
      RATE_LIMIT_KEY: key,
      TURNSTILE_EXPECTED_ACTION: "create_permit",
      TURNSTILE_EXPECTED_HOSTNAME: "secrets.example",
      TURNSTILE_SECRET_KEY: LOCAL_TURNSTILE_DUMMY_SECRET
    };
    expect(() => checkWorkerEnvironment(base)).toThrow("restricted to localhost");
    expect(() => checkWorkerEnvironment({ ...base, EXPECTED_ORIGIN: ORIGIN, TURNSTILE_EXPECTED_HOSTNAME: "secrets.example" })).toThrow("restricted to localhost");
  });

  test("rejects a deployed request URL even when localhost headers are spoofed", async () => {
    const response = await handleApiRequest(new Request("https://deployed.example/api/v2/create-permits", {
      body: JSON.stringify({
        requestId: "00000000-0000-4000-8000-000000000012",
        turnstileResponse: LOCAL_TURNSTILE_DUMMY_TOKEN
      }),
      headers: { "Content-Type": "application/json", Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      method: "POST"
    }), {
      ...workerEnvironment(),
      TURNSTILE_EXPECTED_HOSTNAME: "localhost",
      TURNSTILE_SECRET_KEY: LOCAL_TURNSTILE_DUMMY_SECRET
    }, () => Promise.reject(new Error("must not call Siteverify")));
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "forbidden" });
    expect(response.headers.get("Set-Cookie")).toBeNull();
  });

  test("drives the public create-permit route idempotently with the request ID in Siteverify", async () => {
    const requestId = "00000000-0000-4000-8000-000000000004";
    const challengeTimestamp = new Date().toISOString();
    const siteverifyFetch: typeof fetch = (input, init) => {
      expect(input).toBe("https://challenges.cloudflare.com/turnstile/v0/siteverify");
      if (!(init?.body instanceof FormData)) {
        return Promise.reject(new Error("missing Siteverify form"));
      }
      expect(init.body.get("idempotency_key")).toBe(requestId);
      expect(init.body.get("response")).toBe("turnstile-response");
      expect(init.body.get("secret")).toBe("test-turnstile-secret");
      return Promise.resolve(Response.json({
        action: "create_permit",
        challenge_ts: challengeTimestamp,
        hostname: "localhost",
        success: true
      }));
    };
    const createRequest = () => new Request(`${ORIGIN}/api/v2/create-permits`, {
      body: JSON.stringify({ requestId, turnstileResponse: "turnstile-response" }),
      headers: {
        "Content-Type": "application/json",
        Origin: ORIGIN,
        "Sec-Fetch-Site": "same-origin"
      },
      method: "POST"
    });
    const environment = workerEnvironment();
    const first = await handleApiRequest(createRequest(), environment, siteverifyFetch);
    const second = await handleApiRequest(createRequest(), environment, siteverifyFetch);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(second.headers.get("Set-Cookie")).toBe(first.headers.get("Set-Cookie"));
    expect(await second.json()).toEqual(await first.json());
  });

  test("maps public Siteverify mismatch and outage without leaking upstream details", async () => {
    const createRequest = () => new Request(`${ORIGIN}/api/v2/create-permits`, {
      body: JSON.stringify({
        requestId: "00000000-0000-4000-8000-000000000005",
        turnstileResponse: "turnstile-response"
      }),
      headers: { "Content-Type": "application/json", Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" },
      method: "POST"
    });
    const environment = workerEnvironment();
    const mismatch = await handleApiRequest(createRequest(), environment, () => Promise.resolve(Response.json({
      action: "wrong_action",
      challenge_ts: new Date().toISOString(),
      hostname: "localhost",
      success: true
    })));
    expect(mismatch.status).toBe(403);
    expect(await mismatch.json()).toEqual({ error: "gate_failed" });
    expect(mismatch.headers.get("Set-Cookie")).toBeNull();

    const outage = await handleApiRequest(createRequest(), environment, () => {
      return Promise.reject(new Error("private upstream detail"));
    });
    expect(outage.status).toBe(503);
    expect(await outage.json()).toEqual({ error: "gate_unavailable" });
    expect(outage.headers.get("Set-Cookie")).toBeNull();
  });

  test("accepts only a fresh response for the configured action and hostname", async () => {
    const result = await verifyTurnstile(
      checkedEnvironment(),
      "00000000-0000-4000-8000-000000000001",
      "turnstile-response",
      (_input, init) => {
        expect(init?.method).toBe("POST");
        expect(init?.body).toBeInstanceOf(FormData);
        return Promise.resolve(Response.json({
          action: "create_permit",
          challenge_ts: new Date().toISOString(),
          hostname: "secrets.example",
          success: true
        }));
      }
    );
    expect(result.kind).toBe("accepted");
  });

  test("fails closed on identity mismatch and reports verifier outages separately", async () => {
    const mismatch = await verifyTurnstile(
      checkedEnvironment(),
      "00000000-0000-4000-8000-000000000002",
      "turnstile-response",
      () => Promise.resolve(Response.json({
        action: "wrong_action",
        challenge_ts: new Date().toISOString(),
        hostname: "secrets.example",
        success: true
      }))
    );
    expect(mismatch).toEqual({ kind: "failed" });

    const outage = await verifyTurnstile(
      checkedEnvironment(),
      "00000000-0000-4000-8000-000000000003",
      "turnstile-response",
      () => Promise.reject(new Error("Siteverify unavailable"))
    );
    expect(outage).toEqual({ kind: "unavailable" });
  });
});
