import { afterEach, describe, expect, test } from "vitest";
import envelopeVectors from "../../../vectors/v1/envelopes.json";
import {
  parseDevicePairingClaimResponse,
  parseDevicePairingRedeemResponse,
  parseDevicePermitResponse,
  parseDeviceStatusResponse,
  parsePairingStartResponse
} from "@kryptex/contracts/api";
import { parseKxe1Envelope } from "@kryptex/contracts/envelopes";
import { env, exports } from "cloudflare:workers";
import { reset, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { encodeBase64Url, unixSeconds } from "./core.js";
import { LOCAL_TURNSTILE_DUMMY_SECRET, type WorkerEnv } from "./env.js";
import { secureAssetResponse } from "./http.js";
import { handleApiRequest, LOCAL_TURNSTILE_DUMMY_TOKEN, pagePolicy } from "./index.js";
import { RECORD_KEY, spentRequestKey, type DeviceRecord } from "./state.js";

const ORIGIN = "http://localhost:5173";
const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CLAIM_COOKIE_PATTERN =
  /^kx_device_claim_v3=v3\.[0-9A-HJKMNP-TV-Z]{8}\.[A-Za-z0-9_-]{43}; Max-Age=([0-9]+); Path=\/api\/v3\/devices\/pairings\/claim; Secure; HttpOnly; SameSite=Strict$/u;
const EXPIRED_CLAIM_COOKIE = "kx_device_claim_v3=; Max-Age=0; Path=/api/v3/devices/pairings/claim; Secure; HttpOnly; SameSite=Strict";

afterEach(async () => {
  await reset();
});

const noSiteverify: typeof fetch = () => Promise.reject(new Error("must not call Siteverify"));
const openLimiter: RateLimit = { limit: () => Promise.resolve({ success: true }) };

function localEnvironment(): WorkerEnv {
  return {
    ASSETS: env.ASSETS,
    CAPABILITY_ACTIVE_KEY_ID: "dev-v1",
    CAPABILITY_HMAC_KEYRING: `{"dev-v1":"${key}"}`,
    CIPHERTEXT: env.CIPHERTEXT,
    CREATE_PERMIT_OBJECTS: env.CREATE_PERMIT_OBJECTS,
    DEVICE_OBJECTS: env.DEVICE_OBJECTS,
    DEVICE_PAIRING_OBJECTS: env.DEVICE_PAIRING_OBJECTS,
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

function call(request: Request, environment: WorkerEnv = localEnvironment()): Promise<Response> {
  return handleApiRequest(request, environment, noSiteverify);
}

function filled(length: number, fill: number): string {
  return encodeBase64Url(new Uint8Array(length).fill(fill));
}

function requestId(index: number): string {
  return `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
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

function requestCreateBody(fill: number): object {
  const now = unixSeconds();
  return {
    attemptId: filled(16, fill),
    clientNotAfter: now + 900,
    envelope: schemaEnvelope(now + 900),
    locator: filled(16, fill + 1),
    ownerToken: filled(32, fill + 2),
    settleNotAfter: now + 30,
    ttlSeconds: 900,
    writeToken: filled(32, fill + 3)
  };
}

async function waitForAuthBackoff(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 300);
  });
}

async function startDevicePairing(deviceLocator: string, deviceToken: string, maxDays = 30): Promise<string> {
  const response = await call(nativeRequest("/api/v3/devices/pairings", { deviceLocator, deviceToken, maxDays }));
  expect(response.status).toBe(200);
  expect(response.headers.get("Set-Cookie")).toBeNull();
  return parsePairingStartResponse(await response.json()).userCode;
}

function approve(userCode: string, id: string): Promise<Response> {
  return call(browserRequest("/api/v3/devices/pairings/approve", {
    requestId: id,
    turnstileResponse: LOCAL_TURNSTILE_DUMMY_TOKEN,
    userCode
  }));
}

/** Returns the cookie pair a browser would send back on the claim routes. */
async function approveForClaim(userCode: string, id: string): Promise<string> {
  const response = await approve(userCode, id);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ state: "approved" });
  const setCookie = response.headers.get("Set-Cookie") ?? "";
  expect(setCookie).toMatch(CLAIM_COOKIE_PATTERN);
  return setCookie.split(";", 1)[0] ?? "";
}

function claimStatus(cookie: string): Promise<Response> {
  return call(browserRequest("/api/v3/devices/pairings/claim/status", {}, { Cookie: cookie }));
}

function claim(cookie: string, body: object): Promise<Response> {
  return call(browserRequest("/api/v3/devices/pairings/claim", body, { Cookie: cookie }));
}

function redeem(userCode: string, deviceToken: string): Promise<Response> {
  return call(nativeRequest("/api/v3/devices/pairings/redeem", { deviceToken, userCode }));
}

function mint(deviceLocator: string, deviceToken: string, id: string, environment?: WorkerEnv): Promise<Response> {
  return call(nativeRequest("/api/v3/devices/permits", { deviceLocator, deviceToken, requestId: id }), environment);
}

interface PairedDevice {
  readonly deviceLocator: string;
  readonly deviceToken: string;
  readonly manageToken: string;
}

async function pairDevice(fill: number, days = 30): Promise<PairedDevice> {
  const device = { deviceLocator: filled(16, fill), deviceToken: filled(32, fill + 1), manageToken: filled(32, fill + 2) };
  const userCode = await startDevicePairing(device.deviceLocator, device.deviceToken);
  const cookie = await approveForClaim(userCode, requestId(fill));
  const claimed = await claim(cookie, { days, manageToken: device.manageToken, scope: "device" });
  expect(claimed.status).toBe(200);
  return device;
}

async function mintedPermit(response: Response): Promise<string> {
  expect(response.status).toBe(200);
  return parseDevicePermitResponse(await response.json()).permit;
}

function deviceObject(deviceLocator: string): DurableObjectStub {
  return env.DEVICE_OBJECTS.getByName(`device:${deviceLocator}`);
}

describe("device pairing", () => {
  test("pairs a device grant, mints a permit, and creates a resource with it", async () => {
    const deviceLocator = filled(16, 1);
    const deviceToken = filled(32, 2);
    const manageToken = filled(32, 3);
    const userCode = await startDevicePairing(deviceLocator, deviceToken);

    const pending = await redeem(userCode, deviceToken);
    expect(pending.status).toBe(200);
    expect(parseDevicePairingRedeemResponse(await pending.json()).state).toBe("pending");

    const cookie = await approveForClaim(userCode, requestId(1));
    const stillPending = parseDevicePairingRedeemResponse(await (await redeem(userCode, deviceToken)).json());
    expect(stillPending.state).toBe("pending");

    const status = await claimStatus(cookie);
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ maxDays: 30 });

    const claimed = await claim(cookie, { days: 30, manageToken, scope: "device" });
    expect(claimed.status).toBe(200);
    expect(claimed.headers.get("Set-Cookie")).toBe(EXPIRED_CLAIM_COOKIE);
    expect(claimed.headers.get("Cache-Control")).toBe("no-store");
    const claimResponse = parseDevicePairingClaimResponse(await claimed.json());
    if (claimResponse.scope !== "device") {
      throw new Error("claim did not create a device grant");
    }
    expect(claimResponse.deviceLocator).toBe(deviceLocator);
    expect(claimResponse.deviceExpiresAt - unixSeconds()).toBeGreaterThan(30 * 86_400 - 10);

    const redeemed = parseDevicePairingRedeemResponse(await (await redeem(userCode, deviceToken)).json());
    expect(redeemed).toEqual({ deviceExpiresAt: claimResponse.deviceExpiresAt, state: "device" });

    const permit = await mintedPermit(await mint(deviceLocator, deviceToken, requestId(100)));
    expect(permit.startsWith("v3.")).toBe(true);

    const permitStatus = await call(nativeRequest("/api/v2/create-permits/status", {}, { "Kryptex-Create-Permit": permit }));
    expect(permitStatus.status).toBe(200);
    expect(await permitStatus.json()).toMatchObject({ state: "unused" });

    const created = await call(nativeRequest("/api/v1/requests", requestCreateBody(10), { "Kryptex-Create-Permit": permit }));
    expect(created.status).toBe(200);
    const reused = await call(nativeRequest("/api/v1/requests", requestCreateBody(20), { "Kryptex-Create-Permit": permit }));
    expect(reused.status).toBe(403);
    expect(await reused.json()).toEqual({ error: "creation_permit_required" });

    const replayAfterUse = await mint(deviceLocator, deviceToken, requestId(100));
    expect(replayAfterUse.status).toBe(403);
    expect(await replayAfterUse.json()).toEqual({ error: "creation_permit_required" });

    const deviceStatus = await call(nativeRequest("/api/v3/devices/status", { deviceLocator, deviceToken }));
    expect(deviceStatus.status).toBe(200);
    const parsed = parseDeviceStatusResponse(await deviceStatus.json());
    expect(parsed.state).toBe("active");
    expect(parsed.quotaRemaining).toBe(49);
    expect(parsed.hourlyMints.at(-1)).toBe(1);
    expect(parsed.expiresAt).toBe(claimResponse.deviceExpiresAt);
  });

  test("hands the Turnstile permit to the client when the person picks this transfer only", async () => {
    const deviceToken = filled(32, 12);
    const userCode = await startDevicePairing(filled(16, 11), deviceToken);
    const cookie = await approveForClaim(userCode, requestId(11));

    const claimed = await claim(cookie, { scope: "transfer" });
    expect(claimed.status).toBe(200);
    expect(claimed.headers.get("Set-Cookie")).toBe(EXPIRED_CLAIM_COOKIE);
    expect(await claimed.json()).toEqual({ scope: "transfer" });

    const first = parseDevicePairingRedeemResponse(await (await redeem(userCode, deviceToken)).json());
    const second = parseDevicePairingRedeemResponse(await (await redeem(userCode, deviceToken)).json());
    if (first.state !== "transfer" || second.state !== "transfer") {
      throw new Error("pairing did not hand over a transfer permit");
    }
    expect(first.permit.startsWith("v2.")).toBe(true);
    expect(second.permit).toBe(first.permit);

    const created = await call(nativeRequest("/api/v1/requests", requestCreateBody(30), { "Kryptex-Create-Permit": first.permit }));
    expect(created.status).toBe(200);
    const noGrant = await mint(filled(16, 11), deviceToken, requestId(110));
    expect(noGrant.status).toBe(404);
  });

  test("sets the claim cookie only for the claim routes and the pairing lifetime", async () => {
    const userCode = await startDevicePairing(filled(16, 21), filled(32, 22));
    const response = await approve(userCode, requestId(21));
    const match = CLAIM_COOKIE_PATTERN.exec(response.headers.get("Set-Cookie") ?? "");
    expect(match).not.toBeNull();
    const maxAge = Number(match?.[1]);
    expect(maxAge).toBeGreaterThan(590);
    expect(maxAge).toBeLessThanOrEqual(600);
    expect(response.headers.get("Set-Cookie")).toContain(`v3.${userCode.replace("-", "")}.`);
  });

  test("replaces the claim token on a retried approval and refuses any other approval", async () => {
    const userCode = await startDevicePairing(filled(16, 31), filled(32, 32));
    const firstCookie = await approveForClaim(userCode, requestId(31));
    const secondCookie = await approveForClaim(userCode, requestId(31));
    expect(secondCookie).not.toBe(firstCookie);

    const other = await approve(userCode, requestId(32));
    expect(other.status).toBe(404);
    expect(other.headers.get("Set-Cookie")).toBeNull();

    const stale = await claimStatus(firstCookie);
    expect(stale.status).toBe(404);
    expect(await stale.json()).toEqual({ error: "unavailable" });
    await waitForAuthBackoff();
    expect((await claimStatus(secondCookie)).status).toBe(200);
  });

  test("repeats an identical claim and refuses a different choice", async () => {
    const deviceLocator = filled(16, 41);
    const manageToken = filled(32, 43);
    const userCode = await startDevicePairing(deviceLocator, filled(32, 42), 7);
    const cookie = await approveForClaim(userCode, requestId(41));

    const tooLong = await claim(cookie, { days: 30, manageToken, scope: "device" });
    expect(tooLong.status).toBe(404);

    const first = await claim(cookie, { days: 7, manageToken, scope: "device" });
    expect(first.status).toBe(200);
    const firstBody: unknown = await first.json();
    const repeated = await claim(cookie, { days: 7, manageToken, scope: "device" });
    expect(repeated.status).toBe(200);
    expect(await repeated.json()).toEqual(firstBody);

    for (const body of [{ scope: "transfer" }, { days: 1, manageToken, scope: "device" }, { days: 7, manageToken: filled(32, 44), scope: "device" }]) {
      const mismatch = await claim(cookie, body);
      expect(mismatch.status).toBe(404);
      expect(mismatch.headers.get("Set-Cookie")).toBeNull();
      expect(await mismatch.json()).toEqual({ error: "unavailable" });
    }
    expect((await claimStatus(cookie)).status).toBe(404);
  });

  test("hides a pairing from a missing or malformed claim cookie and a wrong device token", async () => {
    const deviceToken = filled(32, 52);
    const userCode = await startDevicePairing(filled(16, 51), deviceToken);
    await approveForClaim(userCode, requestId(51));
    const compact = userCode.replace("-", "");
    for (const cookie of ["", `kx_device_claim_v3=v2.${compact}.${filled(32, 53)}`, `kx_device_claim_v3=v3.${compact}.${filled(32, 53)}`]) {
      const response = await claimStatus(cookie);
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({ error: "unavailable" });
    }
    const wrong = await redeem(userCode, filled(32, 54));
    expect(wrong.status).toBe(404);
    expect(await wrong.json()).toEqual({ error: "unavailable" });
  });
});

describe("device permits", () => {
  test("replays a mint within the permit lifetime without charging the quota", async () => {
    const device = await pairDevice(61);
    const first = await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(600)));
    const second = await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(600)));
    expect(second).toBe(first);
    const status = parseDeviceStatusResponse(await (await call(nativeRequest("/api/v3/devices/status", {
      deviceLocator: device.deviceLocator,
      deviceToken: device.deviceToken
    }))).json());
    expect(status.quotaRemaining).toBe(49);
  });

  test("refuses to replay a consumed permit and charges nothing for the attempt", async () => {
    const device = await pairDevice(66);
    const permit = await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(660)));
    const created = await call(nativeRequest("/api/v1/requests", requestCreateBody(50), { "Kryptex-Create-Permit": permit }));
    expect(created.status).toBe(200);

    const replay = await mint(device.deviceLocator, device.deviceToken, requestId(660));
    expect(replay.status).toBe(403);
    expect(await replay.json()).toEqual({ error: "creation_permit_required" });
    const status = parseDeviceStatusResponse(await (await call(nativeRequest("/api/v3/devices/status", {
      deviceLocator: device.deviceLocator,
      deviceToken: device.deviceToken
    }))).json());
    expect(status.quotaRemaining).toBe(49);
    expect(status.hourlyMints.reduce((total, count) => total + count, 0)).toBe(1);
  });

  test("refuses a management token as a device token", async () => {
    const device = await pairDevice(67);
    const minted = await mint(device.deviceLocator, device.manageToken, requestId(670));
    expect(minted.status).toBe(404);
    expect(await minted.json()).toEqual({ error: "unavailable" });
  });

  test("refuses one grant's device token on another grant's locator", async () => {
    const first = await pairDevice(68);
    const second = await pairDevice(72);
    const crossed = await mint(second.deviceLocator, first.deviceToken, requestId(680));
    expect(crossed.status).toBe(404);
    expect(await crossed.json()).toEqual({ error: "unavailable" });
    const crossedStatus = await call(nativeRequest("/api/v3/devices/status", {
      deviceLocator: first.deviceLocator,
      manageToken: second.manageToken
    }));
    expect(crossedStatus.status).toBe(404);
  });

  test("rejects a known request ID after the permit lifetime and keeps it only as a spent ID", async () => {
    const device = await pairDevice(71);
    await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(700)));
    await runInDurableObject(deviceObject(device.deviceLocator), async (_instance, state) => {
      const record = await state.storage.get<DeviceRecord>(RECORD_KEY);
      if (record === undefined) {
        throw new Error("missing device record");
      }
      const recentMints = record.recentMints.map((entry) => ({ ...entry, mintedAt: entry.mintedAt - 121 }));
      await state.storage.put(RECORD_KEY, { ...record, recentMints });
    });

    const late = await mint(device.deviceLocator, device.deviceToken, requestId(700));
    expect(late.status).toBe(403);
    expect(await late.json()).toEqual({ error: "creation_permit_required" });
    await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(701)));

    await runInDurableObject(deviceObject(device.deviceLocator), async (_instance, state) => {
      const record = await state.storage.get<DeviceRecord>(RECORD_KEY);
      expect(record?.recentMints.map((entry) => entry.requestId)).toEqual([requestId(701)]);
      expect(await state.storage.get(spentRequestKey(requestId(700)))).toBe(true);
    });
  });

  test("fails closed once 50 permits were minted in the last 24 hours", async () => {
    const device = await pairDevice(81);
    const unlimited = { ...localEnvironment(), EDGE_RATE_LIMITER: openLimiter, LOCATOR_RATE_LIMITER: openLimiter };
    const first = await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(800), unlimited));
    for (let index = 1; index < 50; index += 1) {
      await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(800 + index), unlimited));
    }
    const exhausted = await mint(device.deviceLocator, device.deviceToken, requestId(850), unlimited);
    expect(exhausted.status).toBe(429);
    expect(await exhausted.json()).toEqual({ error: "quota_exhausted" });

    expect(await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(800), unlimited))).toBe(first);
    const status = parseDeviceStatusResponse(await (await call(nativeRequest("/api/v3/devices/status", {
      deviceLocator: device.deviceLocator,
      manageToken: device.manageToken
    }), unlimited)).json());
    expect(status.quotaRemaining).toBe(0);
    expect(status.hourlyMints.reduce((total, count) => total + count, 0)).toBe(50);
  });

  test("stops minting after the person revokes the grant with the management token", async () => {
    const device = await pairDevice(91);
    const manage = { deviceLocator: device.deviceLocator, manageToken: device.manageToken };
    const revoked = await call(browserRequest("/api/v3/devices/revoke", manage));
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toEqual({ state: "revoked" });
    const repeated = await call(browserRequest("/api/v3/devices/revoke", manage));
    expect(await repeated.json()).toEqual({ state: "revoked" });

    const minted = await mint(device.deviceLocator, device.deviceToken, requestId(900));
    expect(minted.status).toBe(404);
    expect(await minted.json()).toEqual({ error: "unavailable" });

    const status = await call(nativeRequest("/api/v3/devices/status", {
      deviceLocator: device.deviceLocator,
      deviceToken: device.deviceToken
    }));
    expect(parseDeviceStatusResponse(await status.json()).state).toBe("revoked");
  });

  test("answers a wrong device token with unavailable and backs off", async () => {
    const device = await pairDevice(101);
    const wrong = await mint(device.deviceLocator, filled(32, 109), requestId(1000));
    expect(wrong.status).toBe(404);
    expect(await wrong.json()).toEqual({ error: "unavailable" });
    const throttled = await mint(device.deviceLocator, device.deviceToken, requestId(1000));
    expect(throttled.status).toBe(429);
    expect(await throttled.json()).toEqual({ error: "rate_limited" });
    await waitForAuthBackoff();
    await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(1000)));

    const unknown = await mint(filled(16, 110), device.deviceToken, requestId(1001));
    expect(unknown.status).toBe(404);
  });

  test("deletes the grant when its alarm runs at expiry", async () => {
    const device = await pairDevice(111);
    const stub = deviceObject(device.deviceLocator);
    await runInDurableObject(stub, async (_instance, state) => {
      const record = await state.storage.get<DeviceRecord>(RECORD_KEY);
      if (record === undefined) {
        throw new Error("missing device record");
      }
      await state.storage.put(RECORD_KEY, { ...record, expiresAt: unixSeconds() - 1 });
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get(RECORD_KEY)).toBeUndefined();
    });
    const status = await call(nativeRequest("/api/v3/devices/status", {
      deviceLocator: device.deviceLocator,
      deviceToken: device.deviceToken
    }));
    expect(status.status).toBe(404);
  });

  test("accepts a device permit only in the native header", async () => {
    const device = await pairDevice(121);
    const permit = await mintedPermit(await mint(device.deviceLocator, device.deviceToken, requestId(1200)));
    const fromBrowser = await call(browserRequest("/api/v2/create-permits/status", {}, { Cookie: `kx_create_v2=${permit}` }));
    expect(fromBrowser.status).toBe(403);
    expect(await fromBrowser.json()).toEqual({ error: "creation_permit_required" });
    const created = await call(browserRequest("/api/v1/requests", requestCreateBody(40), { Cookie: `kx_create_v2=${permit}` }));
    expect(created.status).toBe(403);
    expect(await created.json()).toEqual({ error: "creation_permit_required" });
    const fromNative = await call(nativeRequest("/api/v2/create-permits/status", {}, { "Kryptex-Create-Permit": permit }));
    expect(fromNative.status).toBe(200);
  });
});

describe("device request modes", () => {
  test("keeps browser-only and native-only device routes apart", async () => {
    const deviceLocator = filled(16, 131);
    const deviceToken = filled(32, 132);
    const fromBrowser = await call(browserRequest("/api/v3/devices/pairings", { deviceLocator, deviceToken, maxDays: 30 }));
    expect(fromBrowser.status).toBe(403);
    const userCode = await startDevicePairing(deviceLocator, deviceToken);

    const forbidden = [
      nativeRequest("/api/v3/devices/pairings/approve", {
        requestId: requestId(131),
        turnstileResponse: LOCAL_TURNSTILE_DUMMY_TOKEN,
        userCode
      }),
      nativeRequest("/api/v3/devices/pairings/claim/status", {}),
      nativeRequest("/api/v3/devices/pairings/claim", { scope: "transfer" }),
      browserRequest("/api/v3/devices/pairings/redeem", { deviceToken, userCode }),
      browserRequest("/api/v3/devices/permits", { deviceLocator, deviceToken, requestId: requestId(132) })
    ];
    for (const request of forbidden) {
      const response = await call(request);
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({ error: "forbidden" });
    }

    const crossSiteRevoke = await call(browserRequest("/api/v3/devices/revoke", { deviceLocator, deviceToken }, {
      "Sec-Fetch-Site": "same-site"
    }));
    expect(crossSiteRevoke.status).toBe(403);
    const browserStatus = await call(browserRequest("/api/v3/devices/status", { deviceLocator, manageToken: filled(32, 133) }));
    expect(browserStatus.status).toBe(404);
    expect(await browserStatus.json()).toEqual({ error: "unavailable" });
  });

  test("rejects a grant lifetime outside the allowed set", async () => {
    const response = await call(nativeRequest("/api/v3/devices/pairings", {
      deviceLocator: filled(16, 141),
      deviceToken: filled(32, 142),
      maxDays: 5
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  test("lets the device pairing page reach only its approve route and Turnstile", async () => {
    const policyFor = (pathname: string): string =>
      secureAssetResponse(new Response(""), pagePolicy(pathname, localEnvironment())).headers.get("Content-Security-Policy") ?? "";
    const devicePolicy = policyFor("/pair/device");
    expect(devicePolicy).toContain(
      `connect-src ${ORIGIN}/api/v3/devices/pairings/approve https://challenges.cloudflare.com;`
    );
    expect(devicePolicy).not.toContain("connect-src 'self'");
    expect(devicePolicy).not.toContain("/claim");
    expect(devicePolicy).toContain("script-src 'self' https://challenges.cloudflare.com");
    for (const pathname of ["/pair", "/gate"]) {
      expect(policyFor(pathname)).toContain("connect-src 'self' https://challenges.cloudflare.com;");
    }
    for (const pathname of ["/pair/device/confirm", "/d"]) {
      expect(policyFor(pathname)).not.toContain("challenges.cloudflare.com");
      expect(policyFor(pathname)).toContain("connect-src 'self';");
    }

    const served = await exports.default.fetch(new Request(`${ORIGIN}/pair/device`));
    expect(served.headers.get("Content-Security-Policy")).toBe(devicePolicy);
  });
});
