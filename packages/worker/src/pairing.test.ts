import { afterEach, describe, expect, test } from "vitest";
import envelopeVectors from "../../../vectors/v1/envelopes.json";
import { parsePairingRedeemResponse, parsePairingStartResponse } from "@kryptex/contracts/api";
import { parseKxe1Envelope } from "@kryptex/contracts/envelopes";
import { env } from "cloudflare:workers";
import { reset } from "cloudflare:test";
import { encodeBase64Url, unixSeconds } from "./core.js";
import { LOCAL_TURNSTILE_DUMMY_SECRET, type WorkerEnv } from "./env.js";
import { handleApiRequest, LOCAL_TURNSTILE_DUMMY_TOKEN } from "./index.js";

const ORIGIN = "http://localhost:5173";
const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

afterEach(async () => {
  await reset();
});

const noSiteverify: typeof fetch = () => Promise.reject(new Error("must not call Siteverify"));

function localEnvironment(): WorkerEnv {
  return {
    ASSETS: env.ASSETS,
    CAPABILITY_ACTIVE_KEY_ID: "dev-v1",
    CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}"}`,
    CIPHERTEXT: env.CIPHERTEXT,
    CREATE_PERMIT_OBJECTS: env.CREATE_PERMIT_OBJECTS,
    EDGE_RATE_LIMITER: env.EDGE_RATE_LIMITER,
    EXPECTED_ORIGIN: ORIGIN,
    LOCATOR_RATE_LIMITER: env.LOCATOR_RATE_LIMITER,
    PAIRING_OBJECTS: env.PAIRING_OBJECTS,
    PERMIT_ISSUANCE_ACTIVE_KEY_ID: "dev-v1",
    PERMIT_ISSUANCE_KEYRING: `{"dev-v1":"${key}"}`,
    RATE_LIMIT_KEY: key,
    REQUEST_OBJECTS: env.REQUEST_OBJECTS,
    SEND_OBJECTS: env.SEND_OBJECTS,
    TURNSTILE_EXPECTED_ACTION: "create_permit",
    TURNSTILE_EXPECTED_HOSTNAME: "localhost",
    TURNSTILE_SECRET_KEY: LOCAL_TURNSTILE_DUMMY_SECRET
  };
}

function nativeRequest(pathname: string, body: object, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}${pathname}`, {
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", ...headers },
    method: "POST"
  });
}

function browserRequest(pathname: string, body: object, headers: Record<string, string> = {}): Request {
  return nativeRequest(pathname, body, { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin", ...headers });
}

function call(request: Request): Promise<Response> {
  return handleApiRequest(request, localEnvironment(), noSiteverify);
}

function filled(length: number, fill: number): string {
  return encodeBase64Url(new Uint8Array(length).fill(fill));
}

function schemaEnvelope(clientNotAfter: number): string {
  const vector = envelopeVectors.kxe1.find((candidate) => candidate.id === "request-schema-none");
  if (vector === undefined) {
    throw new Error("missing request schema vector");
  }
  const bytes = Uint8Array.from(parseKxe1Envelope(vector.envelopeBase64url).bytes);
  new DataView(bytes.buffer).setBigUint64(8, BigInt(clientNotAfter));
  return encodeBase64Url(bytes);
}

async function startPairing(pollToken: string): Promise<string> {
  const response = await call(nativeRequest("/api/v2/create-permits/pairings", { pollToken }));
  expect(response.status).toBe(200);
  expect(response.headers.get("Set-Cookie")).toBeNull();
  return parsePairingStartResponse(await response.json()).userCode;
}

function approve(userCode: string, requestId: string): Promise<Response> {
  return call(browserRequest("/api/v2/create-permits/pairings/approve", {
    requestId,
    turnstileResponse: LOCAL_TURNSTILE_DUMMY_TOKEN,
    userCode
  }));
}

async function redeem(userCode: string, pollToken: string): Promise<Response> {
  return call(nativeRequest("/api/v2/create-permits/pairings/redeem", { pollToken, userCode }));
}

describe("browser pairing", () => {
  test("hands one approved permit to the native client that started the pairing", async () => {
    const pollToken = filled(32, 1);
    const userCode = await startPairing(pollToken);

    const pending = await redeem(userCode, pollToken);
    expect(pending.status).toBe(200);
    expect(parsePairingRedeemResponse(await pending.json()).state).toBe("pending");

    const approved = await approve(userCode, "00000000-0000-4000-8000-000000000101");
    expect(approved.status).toBe(200);
    expect(approved.headers.get("Set-Cookie")).toBeNull();
    expect(await approved.json()).toEqual({ state: "approved" });

    const first = parsePairingRedeemResponse(await (await redeem(userCode, pollToken)).json());
    const second = parsePairingRedeemResponse(await (await redeem(userCode, pollToken)).json());
    if (first.state !== "approved" || second.state !== "approved") {
      throw new Error("pairing was not approved");
    }
    expect(second.permit).toBe(first.permit);

    const status = await call(nativeRequest("/api/v2/create-permits/status", {}, { "Kryptex-Create-Permit": first.permit }));
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ state: "unused" });

    const now = unixSeconds();
    const body = {
      attemptId: filled(16, 2),
      clientNotAfter: now + 900,
      envelope: schemaEnvelope(now + 900),
      locator: filled(16, 3),
      ownerToken: filled(32, 4),
      settleNotAfter: now + 30,
      ttlSeconds: 900,
      writeToken: filled(32, 5)
    };
    const created = await call(nativeRequest("/api/v1/requests", body, { "Kryptex-Create-Permit": first.permit }));
    expect(created.status).toBe(200);
    expect(created.headers.get("Set-Cookie")).toBeNull();

    const reused = await call(nativeRequest("/api/v1/requests", { ...body, attemptId: filled(16, 6), locator: filled(16, 7) }, {
      "Kryptex-Create-Permit": first.permit
    }));
    expect(reused.status).toBe(403);
    expect(await reused.json()).toEqual({ error: "creation_permit_required" });
  });

  test("repeats an approval for the same solve and refuses any other", async () => {
    const userCode = await startPairing(filled(32, 11));
    expect((await approve(userCode, "00000000-0000-4000-8000-000000000111")).status).toBe(200);
    expect((await approve(userCode, "00000000-0000-4000-8000-000000000111")).status).toBe(200);
    const other = await approve(userCode, "00000000-0000-4000-8000-000000000112");
    expect(other.status).toBe(404);
    expect(await other.json()).toEqual({ error: "unavailable" });
  });

  test("hides a pairing from a wrong poll token and an unknown code", async () => {
    const userCode = await startPairing(filled(32, 21));
    const wrong = await redeem(userCode, filled(32, 22));
    expect(wrong.status).toBe(404);
    expect(await wrong.json()).toEqual({ error: "unavailable" });
    const unknownCode = userCode === "0000-0000" ? "0000-0001" : "0000-0000";
    expect((await approve(unknownCode, "00000000-0000-4000-8000-000000000121")).status).toBe(404);
  });
});

describe("request modes", () => {
  test("keeps browser-only and native-only routes apart", async () => {
    const startFromBrowser = await call(browserRequest("/api/v2/create-permits/pairings", { pollToken: filled(32, 31) }));
    expect(startFromBrowser.status).toBe(403);
    const userCode = await startPairing(filled(32, 32));
    const approveFromNative = await call(nativeRequest("/api/v2/create-permits/pairings/approve", {
      requestId: "00000000-0000-4000-8000-000000000131",
      turnstileResponse: LOCAL_TURNSTILE_DUMMY_TOKEN,
      userCode
    }));
    expect(approveFromNative.status).toBe(403);
    const permitFromNative = await call(nativeRequest("/api/v2/create-permits", {
      requestId: "00000000-0000-4000-8000-000000000132",
      turnstileResponse: LOCAL_TURNSTILE_DUMMY_TOKEN
    }));
    expect(permitFromNative.status).toBe(403);
  });

  test("rejects requests that mix browser and native signals", async () => {
    const body = { locator: filled(16, 41), ownerToken: filled(32, 42) };
    const cookieWithoutOrigin = await call(nativeRequest("/api/v1/requests/status", body, { Cookie: "kx_create_v2=v2.x" }));
    expect(cookieWithoutOrigin.status).toBe(403);
    const fetchMetadataWithoutOrigin = await call(nativeRequest("/api/v1/requests/status", body, { "Sec-Fetch-Site": "cross-site" }));
    expect(fetchMetadataWithoutOrigin.status).toBe(403);
    const nullOrigin = await call(nativeRequest("/api/v1/requests/status", body, { Origin: "null" }));
    expect(nullOrigin.status).toBe(403);
    const browserWithHeaderPermit = await call(browserRequest("/api/v2/create-permits/status", {}, {
      "Kryptex-Create-Permit": `v2.${filled(32, 43)}`
    }));
    expect(browserWithHeaderPermit.status).toBe(403);
  });

  test("serves bearer routes to native clients without an origin", async () => {
    const response = await call(nativeRequest("/api/v1/requests/status", { locator: filled(16, 51), ownerToken: filled(32, 52) }));
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "unavailable" });
  });
});
