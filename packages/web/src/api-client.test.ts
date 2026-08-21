import { afterEach, describe, expect, it, vi } from "vitest";
import { API_ROUTES } from "@kryptex/contracts/protocol";
import { ApiFailure, KryptexClient } from "./api-client";

const locator = "AAAAAAAAAAAAAAAAAAAAAA";
const token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const attemptId = locator;
const now = 1_800_000_000;
const expiresAt = 1_800_003_600;

function headers(extra?: HeadersInit): Headers {
  const output = new Headers(extra);
  output.set("Kryptex-Server-Time", String(now));
  return output;
}

function inputUrl(input: RequestInfo | URL): URL {
  if (input instanceof Request) return new URL(input.url);
  if (input instanceof URL) return input;
  return new URL(input);
}

async function apiFailure(operation: Promise<unknown>): Promise<ApiFailure> {
  try {
    await operation;
  } catch (error) {
    if (error instanceof ApiFailure) return error;
    throw error;
  }
  throw new Error("Expected API operation to fail");
}

function successResponse(pathname: string): Response {
  if (pathname === API_ROUTES.createPermit) return new Response(`{"permitExpiresAt":${now + 1800},"serverTime":${now}}`, { headers: headers() });
  if (pathname === API_ROUTES.createPermitStatus) return new Response(`{"permitExpiresAt":${now + 1800},"serverTime":${now},"state":"unused"}`, { headers: headers() });
  if (pathname === API_ROUTES.sendCreate || pathname === API_ROUTES.requestCreate) return new Response(`{"serverExpiresAt":${expiresAt}}`, { headers: headers() });
  if (pathname === API_ROUTES.sendRetrieve) return new Response(Uint8Array.of(1, 2, 3), { headers: headers({ "Content-Type": "application/octet-stream", "Kryptex-Remaining-Releases": "2", "Kryptex-Server-Expires-At": String(expiresAt) }) });
  if (pathname === API_ROUTES.sendStatus) return new Response(`{"remainingRetrievals":2,"serverExpiresAt":${expiresAt},"state":"active"}`, { headers: headers({ "Kryptex-State-Checked-At": String(now + 1) }) });
  if (pathname === API_ROUTES.sendShorten || pathname === API_ROUTES.requestShorten) return new Response(`{"serverExpiresAt":${now + 900}}`, { headers: headers() });
  if (pathname === API_ROUTES.sendRevoke || pathname === API_ROUTES.requestRevoke) return new Response('{"state":"revoked"}', { headers: headers() });
  if (pathname === API_ROUTES.requestSchema) return new Response(Uint8Array.of(4, 5), { headers: headers({ "Content-Type": "application/octet-stream", "Kryptex-Server-Expires-At": String(expiresAt) }) });
  if (pathname === API_ROUTES.requestSubmit) return new Response(`{"receipt":"${token}"}`, { headers: headers() });
  if (pathname === API_ROUTES.requestStatus) return new Response(`{"serverExpiresAt":${expiresAt},"state":"submitted"}`, { headers: headers({ "Kryptex-State-Checked-At": String(now + 1) }) });
  if (pathname === API_ROUTES.requestPickup) return new Response(Uint8Array.of(6, 7), { headers: headers({ "Content-Type": "application/octet-stream", "Kryptex-Receipt": token, "Kryptex-Server-Expires-At": String(expiresAt) }) });
  return new Response('{"error":"invalid_request"}', { headers: headers(), status: 404 });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("same-origin API adapter", () => {
  it("uses receiver-independent default fetch invocation", async () => {
    const fetchProbe: typeof fetch = function (this: unknown, input) {
      expect(this).toBeUndefined();
      return Promise.resolve(successResponse(inputUrl(input).pathname));
    };
    vi.stubGlobal("fetch", fetchProbe);
    await new KryptexClient().permitStatus();
  });

  it("posts and parses all fourteen public operations", async () => {
    const calls: string[] = [];
    const fetchStub: typeof fetch = (input, init) => {
      const pathname = inputUrl(input).pathname;
      calls.push(pathname);
      expect(init?.method).toBe("POST");
      expect(init?.credentials).toBe("include");
      expect(new Headers(init?.headers).get("Content-Type")).toBe("application/json");
      return Promise.resolve(successResponse(pathname));
    };
    const client = new KryptexClient(fetchStub, "https://secrets.example");
    await expect(client.createPermit({ requestId: "00000000-0000-4000-8000-000000000001", turnstileResponse: "token" })).resolves.toEqual({ permitExpiresAt: now + 1800, serverTime: now });
    await expect(client.permitStatus()).resolves.toEqual({ permitExpiresAt: now + 1800, serverTime: now, state: "unused" });
    await expect(client.createSend({ attemptId, clientNotAfter: expiresAt, envelope: "send-envelope", locator, manageToken: token, maxRetrievals: 2, retrieveToken: token, settleNotAfter: now + 60, ttlSeconds: 3600 })).resolves.toEqual({ serverExpiresAt: expiresAt });
    await expect(client.retrieveSend({ locator, retrieveToken: token })).resolves.toMatchObject({ metadata: { remainingReleases: 2, serverExpiresAt: expiresAt } });
    await expect(client.sendStatus({ locator, manageToken: token })).resolves.toEqual({ remainingRetrievals: 2, serverExpiresAt: expiresAt, state: "active", stateCheckedAt: now + 1 });
    await expect(client.shortenSend({ locator, manageToken: token, serverExpiresAt: now + 900 })).resolves.toEqual({ serverExpiresAt: now + 900 });
    await expect(client.revokeSend({ locator, manageToken: token })).resolves.toEqual({ state: "revoked" });
    await expect(client.createRequest({ attemptId, clientNotAfter: expiresAt, envelope: "schema-envelope", locator, ownerToken: token, settleNotAfter: now + 60, ttlSeconds: 3600, writeToken: token })).resolves.toEqual({ serverExpiresAt: expiresAt });
    await expect(client.requestSchema({ locator, writeToken: token })).resolves.toMatchObject({ metadata: { serverExpiresAt: expiresAt } });
    await expect(client.submitRequest({ envelope: "response-envelope", locator, writeToken: token })).resolves.toEqual({ receipt: token });
    await expect(client.requestStatus({ locator, ownerToken: token })).resolves.toEqual({ serverExpiresAt: expiresAt, state: "submitted", stateCheckedAt: now + 1 });
    await expect(client.pickupRequest({ locator, ownerToken: token })).resolves.toMatchObject({ metadata: { receipt: token, serverExpiresAt: expiresAt } });
    await expect(client.shortenRequest({ locator, ownerToken: token, serverExpiresAt: now + 900 })).resolves.toEqual({ serverExpiresAt: now + 900 });
    await expect(client.revokeRequest({ locator, ownerToken: token })).resolves.toEqual({ state: "revoked" });
    expect(calls).toHaveLength(14);
    expect(new Set(calls)).toEqual(new Set(Object.values(API_ROUTES)));
  });

  it("distinguishes network ambiguity by operation phase", async () => {
    const failedFetch: typeof fetch = () => Promise.reject(new Error("network"));
    const client = new KryptexClient(failedFetch, "https://secrets.example");
    const mutating = await apiFailure(client.createPermit({ requestId: "00000000-0000-4000-8000-000000000001", turnstileResponse: "token" }));
    const status = await apiFailure(client.permitStatus());
    const schema = await apiFailure(client.requestSchema({ locator, writeToken: token }));
    expect(mutating).toMatchObject({ ambiguous: true, code: "network" });
    expect(status).toMatchObject({ ambiguous: false, code: "network" });
    expect(schema).toMatchObject({ ambiguous: false, code: "network" });
  });

  it("keeps malformed post-dispatch responses ambiguous only for mutating operations", async () => {
    const invalidSuccess: typeof fetch = () => Promise.resolve(new Response("{}", { headers: headers() }));
    const mutating = await apiFailure(new KryptexClient(invalidSuccess, "https://secrets.example").createSend({ attemptId, clientNotAfter: expiresAt, envelope: "send-envelope", locator, manageToken: token, maxRetrievals: 1, retrieveToken: token, settleNotAfter: now + 60, ttlSeconds: 3600 }));
    const nonConsuming = await apiFailure(new KryptexClient(invalidSuccess, "https://secrets.example").permitStatus());
    expect(mutating).toMatchObject({ ambiguous: true, code: "invalid_response" });
    expect(nonConsuming).toMatchObject({ ambiguous: false, code: "invalid_response" });

    const invalidError: typeof fetch = () => Promise.resolve(new Response("not-json", { headers: headers(), status: 503 }));
    const invalidMutatingError = await apiFailure(new KryptexClient(invalidError, "https://secrets.example").shortenSend({ locator, manageToken: token, serverExpiresAt: now + 1 }));
    const invalidSchemaError = await apiFailure(new KryptexClient(invalidError, "https://secrets.example").requestSchema({ locator, writeToken: token }));
    expect(invalidMutatingError).toMatchObject({ ambiguous: true, code: "invalid_response" });
    expect(invalidSchemaError).toMatchObject({ ambiguous: false, code: "invalid_response" });
  });

  it("classifies valid server errors and binary metadata failures", async () => {
    const unavailable: typeof fetch = () => Promise.resolve(new Response('{"error":"unavailable"}', { headers: headers(), status: 503 }));
    const mutatingServerError = await apiFailure(new KryptexClient(unavailable, "https://secrets.example").revokeRequest({ locator, ownerToken: token }));
    const nonConsumingServerError = await apiFailure(new KryptexClient(unavailable, "https://secrets.example").requestSchema({ locator, writeToken: token }));
    expect(mutatingServerError).toMatchObject({ ambiguous: true, code: "unavailable" });
    expect(nonConsumingServerError).toMatchObject({ ambiguous: false, code: "unavailable" });

    const badBinary: typeof fetch = () => Promise.resolve(new Response(Uint8Array.of(1), { headers: headers({ "Content-Type": "application/octet-stream" }) }));
    const retrieve = await apiFailure(new KryptexClient(badBinary, "https://secrets.example").retrieveSend({ locator, retrieveToken: token }));
    const schema = await apiFailure(new KryptexClient(badBinary, "https://secrets.example").requestSchema({ locator, writeToken: token }));
    expect(retrieve).toMatchObject({ ambiguous: true, code: "invalid_response" });
    expect(schema).toMatchObject({ ambiguous: false, code: "invalid_response" });
  });

  it("retries gate_unavailable with the caller-owned request identity", async () => {
    const bodies: string[] = [];
    let call = 0;
    const fetchStub: typeof fetch = (_input, init) => {
      if (typeof init?.body === "string") bodies.push(init.body);
      call += 1;
      return Promise.resolve(call === 1
        ? new Response('{"error":"gate_unavailable"}', { headers: headers(), status: 503 })
        : new Response(`{"permitExpiresAt":${now + 1800},"serverTime":${now}}`, { headers: headers() }));
    };
    const client = new KryptexClient(fetchStub, "https://secrets.example");
    const input = { requestId: "00000000-0000-4000-8000-000000000001", turnstileResponse: "same-token" };
    expect(await apiFailure(client.createPermit(input))).toMatchObject({ ambiguous: true, code: "gate_unavailable" });
    await expect(client.createPermit(input)).resolves.toBeDefined();
    expect(bodies).toEqual([JSON.stringify(input), JSON.stringify(input)]);
  });
});
