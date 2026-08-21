import { describe, expect, test } from "vitest";
import envelopeVectors from "../../../vectors/v1/envelopes.json";
import serverVectors from "../../../vectors/v1/server-tags.json";
import { parseKxe1Envelope, parseKxr1Envelope } from "@kryptex/contracts/envelopes";
import { env, exports } from "cloudflare:workers";
import { derivePermitFromSeed, encodeBase64Url, unixSeconds } from "./core.js";
import {
  edgeLimitAllows,
  edgeLimitKey,
  locatorLimitAllows,
  locatorLimitKey,
  normalizeClientNetwork
} from "./index.js";

const ORIGIN = "http://localhost:5173";
const ATTEMPT_ID = "AAECAwQFBgcICQoLDA0ODw";

function envelopeAt(encoded: string, timestamp: number, type: "kxe1" | "kxr1"): string {
  const parsed = type === "kxe1" ? parseKxe1Envelope(encoded) : parseKxr1Envelope(encoded);
  const bytes = Uint8Array.from(parsed.bytes);
  new DataView(bytes.buffer).setBigUint64(8, BigInt(timestamp));
  return encodeBase64Url(bytes);
}

function apiRequest(pathname: string, body: object, cookie?: string): Request {
  const headers = new Headers({
    "Content-Type": "application/json",
    Origin: ORIGIN,
    "Sec-Fetch-Site": "same-origin"
  });
  if (cookie !== undefined) {
    headers.set("Cookie", cookie);
  }
  return new Request(`${ORIGIN}${pathname}`, {
    body: JSON.stringify(body),
    headers,
    method: "POST"
  });
}

async function creationCookie(fill: number): Promise<string> {
  const seed = new Uint8Array(32).fill(fill);
  const material = await derivePermitFromSeed(seed);
  const locator = encodeBase64Url(material.locator);
  const response = await env.CREATE_PERMIT_OBJECTS.getByName(locator).fetch("https://durable-object.invalid/init", {
    body: JSON.stringify({
      locator,
      permitExpiresAt: unixSeconds() + 1800,
      token: encodeBase64Url(material.token)
    }),
    headers: { "Content-Type": "application/json" },
    method: "POST"
  });
  expect(response.status).toBe(200);
  return `kx_create_v2=v2.${encodeBase64Url(seed)}`;
}

function vectorById(id: string): string {
  const vector = envelopeVectors.kxe1.find((candidate) => candidate.id === id);
  if (vector === undefined) {
    throw new Error(`missing envelope vector ${id}`);
  }
  return vector.envelopeBase64url;
}

function serverTag(id: string): { readonly locator: string; readonly token: string } {
  const vector = serverVectors.capabilityTags.find((candidate) => candidate.id === id);
  if (vector === undefined) {
    throw new Error(`missing server vector ${id}`);
  }
  return { locator: vector.locatorBase64url, token: vector.tokenBase64url };
}

function filledBase64Url(length: number, fill: number): string {
  return encodeBase64Url(new Uint8Array(length).fill(fill));
}

async function waitForAuthBackoff(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 300);
  });
}

describe("send routes and release linearization", () => {
  test("commits one send and releases its ciphertext at most once", async () => {
    const now = unixSeconds();
    const retrieve = serverTag("send-retrieve-random-factor");
    const manage = serverTag("send-manage");
    const envelope = envelopeAt(vectorById("send-none"), now + 900, "kxe1");
    const cookie = await creationCookie(7);
    const permitStatus = await exports.default.fetch(apiRequest("/api/v2/create-permits/status", {}, cookie));
    expect(permitStatus.status).toBe(200);
    expect(await permitStatus.json()).toMatchObject({ state: "unused" });

    const created = await exports.default.fetch(apiRequest("/api/v1/sends", {
      attemptId: ATTEMPT_ID,
      clientNotAfter: now + 900,
      envelope,
      locator: retrieve.locator,
      manageToken: manage.token,
      maxRetrievals: 1,
      retrieveToken: retrieve.token,
      settleNotAfter: now + 30,
      ttlSeconds: 900
    }, cookie));
    expect(created.status).toBe(200);
    expect(created.headers.get("Set-Cookie")).toContain("Max-Age=0");

    const releases = await Promise.all([
      exports.default.fetch(apiRequest("/api/v1/sends/retrieve", {
        locator: retrieve.locator,
        retrieveToken: retrieve.token
      })),
      exports.default.fetch(apiRequest("/api/v1/sends/retrieve", {
        locator: retrieve.locator,
        retrieveToken: retrieve.token
      }))
    ]);
    expect(releases.filter((response) => response.status === 200)).toHaveLength(1);
    const winner = releases.find((response) => response.status === 200);
    if (winner === undefined) {
      throw new Error("missing winning release");
    }
    expect(winner.headers.get("Kryptex-Remaining-Releases")).toBe("0");
    expect(encodeBase64Url(new Uint8Array(await winner.arrayBuffer()))).toBe(envelope);

    await waitForAuthBackoff();
    const status = await exports.default.fetch(apiRequest("/api/v1/sends/status", {
      locator: manage.locator,
      manageToken: manage.token
    }));
    expect(status.status).toBe(200);
    expect(status.headers.get("Kryptex-State-Checked-At")).toMatch(/^[0-9]+$/u);
    expect(await status.json()).toMatchObject({ remainingRetrievals: 0, state: "exhausted" });
  });

  test("decrements every release through the final CAS for counts greater than one", async () => {
    const now = unixSeconds();
    const locator = filledBase64Url(16, 21);
    const retrieveToken = filledBase64Url(32, 22);
    const manageToken = filledBase64Url(32, 23);
    const envelope = envelopeAt(vectorById("send-random-factor"), now + 900, "kxe1");
    const created = await exports.default.fetch(apiRequest("/api/v1/sends", {
      attemptId: filledBase64Url(16, 24),
      clientNotAfter: now + 900,
      envelope,
      locator,
      manageToken,
      maxRetrievals: 3,
      retrieveToken,
      settleNotAfter: now + 30,
      ttlSeconds: 900
    }, await creationCookie(10)));
    expect(created.status).toBe(200);

    for (const remaining of [2, 1, 0]) {
      const response = await exports.default.fetch(apiRequest("/api/v1/sends/retrieve", { locator, retrieveToken }));
      expect(response.status).toBe(200);
      expect(response.headers.get("Kryptex-Remaining-Releases")).toBe(String(remaining));
      await response.arrayBuffer();
    }
    const exhausted = await exports.default.fetch(apiRequest("/api/v1/sends/retrieve", { locator, retrieveToken }));
    expect(exhausted.status).toBe(404);
  });
});

describe("management transitions", () => {
  test("shortens and revokes send and request resources without releasing ciphertext", async () => {
    const now = unixSeconds();
    const sendLocator = filledBase64Url(16, 31);
    const sendRetrieveToken = filledBase64Url(32, 32);
    const sendManageToken = filledBase64Url(32, 33);
    const sendEnvelope = envelopeAt(vectorById("send-passphrase"), now + 900, "kxe1");
    const sendCreated = await exports.default.fetch(apiRequest("/api/v1/sends", {
      attemptId: filledBase64Url(16, 34),
      clientNotAfter: now + 900,
      envelope: sendEnvelope,
      locator: sendLocator,
      manageToken: sendManageToken,
      maxRetrievals: 2,
      retrieveToken: sendRetrieveToken,
      settleNotAfter: now + 30,
      ttlSeconds: 900
    }, await creationCookie(11)));
    expect(sendCreated.status).toBe(200);

    const sendShortened = await exports.default.fetch(apiRequest("/api/v1/sends/shorten", {
      locator: sendLocator,
      manageToken: sendManageToken,
      serverExpiresAt: now + 450
    }));
    expect(await sendShortened.json()).toEqual({ serverExpiresAt: now + 450 });
    const sendRevoked = await exports.default.fetch(apiRequest("/api/v1/sends/revoke", {
      locator: sendLocator,
      manageToken: sendManageToken
    }));
    expect(await sendRevoked.json()).toEqual({ state: "revoked" });
    const sendStatus = await exports.default.fetch(apiRequest("/api/v1/sends/status", {
      locator: sendLocator,
      manageToken: sendManageToken
    }));
    expect(await sendStatus.json()).toMatchObject({ serverExpiresAt: now + 450, state: "revoked" });
    const deniedRelease = await exports.default.fetch(apiRequest("/api/v1/sends/retrieve", {
      locator: sendLocator,
      retrieveToken: sendRetrieveToken
    }));
    expect(deniedRelease.status).toBe(404);

    const requestLocator = filledBase64Url(16, 41);
    const writeToken = filledBase64Url(32, 42);
    const ownerToken = filledBase64Url(32, 43);
    const schemaEnvelope = envelopeAt(vectorById("request-schema-passphrase"), now + 900, "kxe1");
    const requestCreated = await exports.default.fetch(apiRequest("/api/v1/requests", {
      attemptId: filledBase64Url(16, 44),
      clientNotAfter: now + 900,
      envelope: schemaEnvelope,
      locator: requestLocator,
      ownerToken,
      settleNotAfter: now + 30,
      ttlSeconds: 900,
      writeToken
    }, await creationCookie(12)));
    expect(requestCreated.status).toBe(200);
    const requestShortened = await exports.default.fetch(apiRequest("/api/v1/requests/shorten", {
      locator: requestLocator,
      ownerToken,
      serverExpiresAt: now + 450
    }));
    expect(await requestShortened.json()).toEqual({ serverExpiresAt: now + 450 });
    const requestRevoked = await exports.default.fetch(apiRequest("/api/v1/requests/revoke", {
      locator: requestLocator,
      ownerToken
    }));
    expect(await requestRevoked.json()).toEqual({ state: "revoked" });
    const requestStatus = await exports.default.fetch(apiRequest("/api/v1/requests/status", {
      locator: requestLocator,
      ownerToken
    }));
    expect(await requestStatus.json()).toMatchObject({ serverExpiresAt: now + 450, state: "revoked" });
    const deniedSchema = await exports.default.fetch(apiRequest("/api/v1/requests/schema", {
      locator: requestLocator,
      writeToken
    }));
    expect(deniedSchema.status).toBe(404);
  });
});

describe("write-once request routes", () => {
  test("allows one submission and one pickup while schema reads stay non-consuming", async () => {
    const now = unixSeconds();
    const write = serverTag("request-write-passphrase");
    const owner = serverTag("request-owner");
    const schemaEnvelope = envelopeAt(vectorById("request-schema-none"), now + 900, "kxe1");
    const responseEnvelope = envelopeAt(envelopeVectors.kxr1.envelopeBase64url, now + 900, "kxr1");
    const created = await exports.default.fetch(apiRequest("/api/v1/requests", {
      attemptId: ATTEMPT_ID,
      clientNotAfter: now + 900,
      envelope: schemaEnvelope,
      locator: write.locator,
      ownerToken: owner.token,
      settleNotAfter: now + 30,
      ttlSeconds: 900,
      writeToken: write.token
    }, await creationCookie(9)));
    expect(created.status).toBe(200);

    const schemaReads = await Promise.all([
      exports.default.fetch(apiRequest("/api/v1/requests/schema", {
        locator: write.locator,
        writeToken: write.token
      })),
      exports.default.fetch(apiRequest("/api/v1/requests/schema", {
        locator: write.locator,
        writeToken: write.token
      }))
    ]);
    expect(schemaReads.filter((response) => response.status === 200)).toHaveLength(2);
    const retrySchema = await exports.default.fetch(apiRequest("/api/v1/requests/schema", {
      locator: write.locator,
      writeToken: write.token
    }));
    expect(retrySchema.status).toBe(200);
    expect(encodeBase64Url(new Uint8Array(await retrySchema.arrayBuffer()))).toBe(schemaEnvelope);

    const submissions = await Promise.all([
      exports.default.fetch(apiRequest("/api/v1/requests/submit", {
        envelope: responseEnvelope,
        locator: write.locator,
        writeToken: write.token
      })),
      exports.default.fetch(apiRequest("/api/v1/requests/submit", {
        envelope: responseEnvelope,
        locator: write.locator,
        writeToken: write.token
      }))
    ]);
    expect(submissions.filter((response) => response.status === 200)).toHaveLength(1);

    await waitForAuthBackoff();
    const submittedStatus = await exports.default.fetch(apiRequest("/api/v1/requests/status", {
      locator: owner.locator,
      ownerToken: owner.token
    }));
    expect(await submittedStatus.json()).toMatchObject({ state: "submitted" });

    const pickups = await Promise.all([
      exports.default.fetch(apiRequest("/api/v1/requests/pickup", {
        locator: owner.locator,
        ownerToken: owner.token
      })),
      exports.default.fetch(apiRequest("/api/v1/requests/pickup", {
        locator: owner.locator,
        ownerToken: owner.token
      }))
    ]);
    expect(pickups.filter((response) => response.status === 200)).toHaveLength(1);
    const pickup = pickups.find((response) => response.status === 200);
    if (pickup === undefined) {
      throw new Error("missing winning pickup");
    }
    expect(encodeBase64Url(new Uint8Array(await pickup.arrayBuffer()))).toBe(responseEnvelope);
    expect(pickup.headers.get("Kryptex-Receipt")).toMatch(/^[A-Za-z0-9_-]{43}$/u);

    await waitForAuthBackoff();
    const pickedUpStatus = await exports.default.fetch(apiRequest("/api/v1/requests/status", {
      locator: owner.locator,
      ownerToken: owner.token
    }));
    expect(await pickedUpStatus.json()).toMatchObject({ state: "picked_up" });
  });
});

describe("public request rejection", () => {
  test("consumes a creation permit at most once under a race", async () => {
    const now = unixSeconds();
    const cookie = await creationCookie(18);
    const create = (fill: number) => exports.default.fetch(apiRequest("/api/v1/sends", {
      attemptId: filledBase64Url(16, fill + 3),
      clientNotAfter: now + 900,
      envelope: envelopeAt(vectorById("send-none"), now + 900, "kxe1"),
      locator: filledBase64Url(16, fill),
      manageToken: filledBase64Url(32, fill + 1),
      maxRetrievals: 1,
      retrieveToken: filledBase64Url(32, fill + 2),
      settleNotAfter: now + 30,
      ttlSeconds: 900
    }, cookie));
    const results = await Promise.all([create(91), create(101)]);
    expect(results.filter((response) => response.status === 200)).toHaveLength(1);
    expect(results.filter((response) => response.status === 403 || response.status === 429)).toHaveLength(1);
  });

  test("rejects malformed JSON before Durable Object lookup", async () => {
    const response = await exports.default.fetch(new Request(`${ORIGIN}/api/v1/sends/retrieve`, {
      body: "{}",
      headers: { "Content-Type": "application/json", Origin: ORIGIN },
      method: "POST"
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  test("stops an oversized chunked body before JSON parsing", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(8_000).fill(0x20));
        controller.enqueue(new Uint8Array(300).fill(0x20));
        controller.close();
      }
    });
    const response = await exports.default.fetch(new Request(`${ORIGIN}/api/v1/sends/status`, {
      body,
      headers: { "Content-Type": "application/json", Origin: ORIGIN },
      method: "POST"
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  test("rejects malformed UTF-8 with a fixed invalid request", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x7d]));
        controller.close();
      }
    });
    const response = await exports.default.fetch(new Request(`${ORIGIN}/api/v1/sends/status`, {
      body,
      headers: { "Content-Type": "application/json", Origin: ORIGIN },
      method: "POST"
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  test("rejects cross-site mutation metadata before consuming a permit", async () => {
    const response = await exports.default.fetch(new Request(`${ORIGIN}/api/v1/sends/retrieve`, {
      body: "{}",
      headers: {
        "Content-Type": "application/json",
        Origin: ORIGIN,
        "Sec-Fetch-Site": "cross-site"
      },
      method: "POST"
    }));
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "forbidden" });
    expect(response.headers.get("Kryptex-Server-Time")).toMatch(/^[0-9]+$/u);
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Strict-Transport-Security")).toBe("max-age=63072000; includeSubDomains");
  });

  test("rejects API query strings before parsing the request body", async () => {
    const response = await exports.default.fetch(new Request(`${ORIGIN}/api/v1/sends/retrieve?capability=must-not-be-accepted`, {
      body: "not-json",
      headers: { "Content-Type": "application/json", Origin: ORIGIN },
      method: "POST"
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  test("rejects an untrusted origin and an invalid permit cookie with fixed errors", async () => {
    const wrongOrigin = await exports.default.fetch(new Request(`${ORIGIN}/api/v1/sends/retrieve`, {
      body: JSON.stringify({ locator: filledBase64Url(16, 61), retrieveToken: filledBase64Url(32, 62) }),
      headers: { "Content-Type": "application/json", Origin: "https://attacker.invalid" },
      method: "POST"
    }));
    expect(wrongOrigin.status).toBe(403);
    expect(await wrongOrigin.json()).toEqual({ error: "forbidden" });

    const invalidCookie = await exports.default.fetch(apiRequest("/api/v1/sends", {
      attemptId: filledBase64Url(16, 63),
      clientNotAfter: unixSeconds() + 900,
      envelope: envelopeAt(vectorById("send-none"), unixSeconds() + 900, "kxe1"),
      locator: filledBase64Url(16, 64),
      manageToken: filledBase64Url(32, 65),
      maxRetrievals: 1,
      retrieveToken: filledBase64Url(32, 66),
      settleNotAfter: unixSeconds() + 30,
      ttlSeconds: 900
    }, "kx_create_v2=v2.not-a-valid-seed"));
    expect(invalidCookie.status).toBe(403);
    expect(await invalidCookie.json()).toEqual({ error: "creation_permit_required" });
    expect(invalidCookie.headers.get("Cache-Control")).toBe("no-store");

    const retiredCookie = await exports.default.fetch(apiRequest(
      "/api/v2/create-permits/status",
      {},
      `kx_create=v1.${filledBase64Url(32, 67)}`
    ));
    expect(retiredCookie.status).toBe(403);
    expect(await retiredCookie.json()).toEqual({ error: "creation_permit_required" });
  });

  test("applies exact per-resource authorization backoff", async () => {
    const locator = filledBase64Url(16, 71);
    const token = filledBase64Url(32, 72);
    const first = await exports.default.fetch(apiRequest("/api/v1/sends/status", { locator, manageToken: token }));
    const second = await exports.default.fetch(apiRequest("/api/v1/sends/status", { locator, manageToken: token }));
    expect(first.status).toBe(404);
    expect(first.headers.get("Kryptex-State-Checked-At")).toMatch(/^[0-9]+$/u);
    expect(second.status).toBe(429);
  });
});

describe("edge limiter identity", () => {
  test("coarsens IPv4 and IPv6 identities without accepting malformed addresses", () => {
    expect(normalizeClientNetwork("192.0.2.149")).toBe("ipv4:192.0.2.0/24");
    expect(normalizeClientNetwork("2001:db8:1234:5678:9abc:def0:1234:5678")).toBe("ipv6:2001:0db8:1234:5678::/64");
    expect(normalizeClientNetwork("2001:db8:1234:5678::1")).toBe("ipv6:2001:0db8:1234:5678::/64");
    expect(normalizeClientNetwork("::ffff:192.0.2.1")).toBe("ipv6:0000:0000:0000:0000::/64");
    expect(normalizeClientNetwork("999.1.2.3")).toBe("unknown");
    expect(normalizeClientNetwork("2001::db8::1")).toBe("unknown");
    expect(normalizeClientNetwork(null)).toBe("unknown");
  });

  test("keys only by coarse client network and route and fails open on binding errors", async () => {
    expect(edgeLimitKey("/api/v1/sends/status", "192.0.2.149")).toBe(
      "/api/v1/sends/status\u0000ipv4:192.0.2.0/24"
    );
    expect(await edgeLimitAllows({
      limit() {
        return Promise.reject(new Error("rate limit binding unavailable"));
      }
    }, "route\u0000network")).toBe(true);
    expect(await edgeLimitAllows({
      limit() {
        return Promise.resolve({ success: false });
      }
    }, "route\u0000network")).toBe(false);
  });

  test("uses only the frozen blinded locator tag for the resource limiter", async () => {
    const locator = filledBase64Url(16, 119);
    const sendKey = await locatorLimitKey(new Uint8Array(32), 1, locator);
    const requestKey = await locatorLimitKey(new Uint8Array(32), 2, locator);
    expect(sendKey).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(sendKey).not.toContain(locator);
    expect(requestKey).not.toBe(sendKey);

    let observedKey = "";
    expect(await locatorLimitAllows({
      limit(options) {
        observedKey = options.key;
        return Promise.resolve({ success: true });
      }
    }, new Uint8Array(32), 1, locator)).toBe(true);
    expect(observedKey).toBe(sendKey);
    expect(await locatorLimitAllows({
      limit() {
        return Promise.reject(new Error("locator limiter unavailable"));
      }
    }, new Uint8Array(32), 1, locator)).toBe(true);
  });
});
