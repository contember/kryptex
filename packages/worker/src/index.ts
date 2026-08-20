import {
  parseCreatePermitRequestJson,
  parseEmptyRequestJson,
  parseRequestCreateRequestJson,
  parseRequestOwnerRequestJson,
  parseRequestShortenRequestJson,
  parseRequestSubmitRequestJson,
  parseRequestWriteRequestJson,
  parseSendCreateRequestJson,
  parseSendManageRequestJson,
  parseSendRetrieveRequestJson,
  parseSendShortenRequestJson
} from "@kryptex/contracts/api";
import { API_ROUTES } from "@kryptex/contracts/protocol";
import { CreatePermitDurableObject } from "./permit-object.js";
import { RequestDurableObject } from "./request-object.js";
import { SendDurableObject } from "./send-object.js";
import {
  decodeUuid,
  blindedLocator,
  derivePermitFromSeed,
  derivePermitMaterial,
  encodeBase64Url,
  randomBase64Url,
  unixSeconds
} from "./core.js";
import { checkWorkerEnvironment, type CheckedWorkerEnvironment, type WorkerEnv } from "./env.js";
import {
  apiError,
  expiredPermitCookie,
  finalizeApiResponse,
  normalizeBindingResponse,
  permitCookie,
  rateLimited,
  secureAssetResponse
} from "./http.js";
import { decodeCanonicalBase64Url, parseJson, property } from "./strict.js";

export { CreatePermitDurableObject, RequestDurableObject, SendDurableObject };

const MAX_SMALL_BODY_BYTES = 8_192;
const MAX_ENVELOPE_BODY_BYTES = 1_500_000;
const MUTATING_ROUTES: ReadonlySet<string> = new Set([
  API_ROUTES.createPermit,
  API_ROUTES.sendCreate,
  API_ROUTES.sendRetrieve,
  API_ROUTES.sendRevoke,
  API_ROUTES.sendShorten,
  API_ROUTES.requestCreate,
  API_ROUTES.requestSubmit,
  API_ROUTES.requestPickup,
  API_ROUTES.requestRevoke,
  API_ROUTES.requestShorten
]);

type TurnstileResult =
  | { readonly kind: "accepted"; readonly permitExpiresAt: number }
  | { readonly kind: "failed" }
  | { readonly kind: "unavailable" };

function isEnvelopeRoute(pathname: string): boolean {
  return pathname === API_ROUTES.sendCreate || pathname === API_ROUTES.requestCreate || pathname === API_ROUTES.requestSubmit;
}

async function readBody(request: Request, maximumBytes: number): Promise<string> {
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new Error("invalid content type");
  }
  const declaredLength = request.headers.get("Content-Length");
  if (declaredLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) > maximumBytes) {
      throw new Error("body too large");
    }
  }
  if (request.body === null) {
    return "";
  }
  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let byteLength = 0;
  let text = "";
  try {
    let chunk = await reader.read();
    while (!chunk.done) {
      byteLength += chunk.value.byteLength;
      if (byteLength > maximumBytes) {
        await reader.cancel();
        throw new Error("body too large");
      }
      text += decoder.decode(chunk.value, { stream: true });
      chunk = await reader.read();
    }
    text += decoder.decode();
    return text;
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // Cancellation is best effort after rejecting the body.
    }
    throw error;
  }
}

function permitSeedFromCookie(request: Request): string | null {
  const cookie = request.headers.get("Cookie");
  if (cookie === null) {
    return null;
  }
  const values = cookie
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith("kx_create="))
    .map((part) => part.slice("kx_create=".length));
  if (values.length !== 1) {
    return null;
  }
  const value = values[0];
  if (!value?.startsWith("v1.")) {
    return null;
  }
  const seed = value.slice(3);
  try {
    decodeCanonicalBase64Url(seed, 32, "permit seed");
    return seed;
  } catch {
    return null;
  }
}

async function permitFromSeed(seed: string): Promise<{ readonly locator: string; readonly token: string }> {
  const material = await derivePermitFromSeed(decodeCanonicalBase64Url(seed, 32, "permit seed"));
  return { locator: encodeBase64Url(material.locator), token: encodeBase64Url(material.token) };
}

async function invokeRaw(stub: DurableObjectStub, action: string, body: object): Promise<Response> {
  return stub.fetch(`https://durable-object.invalid/${action}`, {
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" },
    method: "POST"
  });
}

async function invoke(stub: DurableObjectStub, action: string, body: object): Promise<Response> {
  return normalizeBindingResponse(await invokeRaw(stub, action, body));
}

async function invokeWithRetry(stub: DurableObjectStub, action: string, body: object): Promise<Response> {
  try {
    const response = await invokeRaw(stub, action, body);
    return normalizeBindingResponse(response.status >= 500 ? await invokeRaw(stub, action, body) : response);
  } catch {
    return normalizeBindingResponse(await invokeRaw(stub, action, body));
  }
}

function stubFor(namespace: DurableObjectNamespace, locator: string): DurableObjectStub {
  return namespace.get(namespace.idFromName(locator));
}

export async function verifyTurnstile(
  environment: CheckedWorkerEnvironment,
  requestId: string,
  responseToken: string,
  siteverifyFetch: typeof fetch
): Promise<TurnstileResult> {
  const body = new FormData();
  body.set("secret", environment.turnstileSecretKey);
  body.set("response", responseToken);
  body.set("idempotency_key", requestId);
  let response: Response;
  try {
    response = await siteverifyFetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      body,
      method: "POST",
      signal: AbortSignal.timeout(5_000)
    });
  } catch {
    return { kind: "unavailable" };
  }
  if (!response.ok) {
    return { kind: "unavailable" };
  }
  try {
    const value = parseJson(await response.text());
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return { kind: "unavailable" };
    }
    const success = property(value, "success", "Siteverify response");
    const hostname = property(value, "hostname", "Siteverify response");
    const action = property(value, "action", "Siteverify response");
    const challengeTimestamp = property(value, "challenge_ts", "Siteverify response");
    if (success !== true || hostname !== environment.turnstileHostname || action !== environment.turnstileAction) {
      return { kind: "failed" };
    }
    if (typeof challengeTimestamp !== "string") {
      return { kind: "unavailable" };
    }
    const challengeTimeMs = Date.parse(challengeTimestamp);
    if (!Number.isFinite(challengeTimeMs)) {
      return { kind: "unavailable" };
    }
    const now = unixSeconds();
    const permitExpiresAt = Math.min(now + 300, Math.floor(challengeTimeMs / 1_000) + 300);
    return permitExpiresAt > now ? { kind: "accepted", permitExpiresAt } : { kind: "failed" };
  } catch {
    return { kind: "unavailable" };
  }
}

function validateCreationTimes(
  input: { readonly clientNotAfter: number; readonly settleNotAfter: number; readonly ttlSeconds: number },
  now: number
): boolean {
  return input.settleNotAfter >= now + 15 &&
    input.settleNotAfter <= now + 90 &&
    input.clientNotAfter >= now + input.ttlSeconds - 300 &&
    input.clientNotAfter <= now + input.ttlSeconds + 300;
}

interface EdgeRateLimiter {
  limit(options: { readonly key: string }): Promise<{ readonly success: boolean }>;
}

export function edgeLimitKey(route: string, clientAddress: string | null): string {
  return `${route}\u0000${normalizeClientNetwork(clientAddress)}`;
}

export async function edgeLimitAllows(limiter: EdgeRateLimiter, key: string): Promise<boolean> {
  try {
    const outcome = await limiter.limit({ key });
    return outcome.success;
  } catch {
    return true;
  }
}

async function passEdgeLimit(environment: WorkerEnv, request: Request, route: string): Promise<boolean> {
  return edgeLimitAllows(environment.EDGE_RATE_LIMITER, edgeLimitKey(route, request.headers.get("CF-Connecting-IP")));
}

function bearerLocator(route: string, text: string): { readonly locator: string; readonly resourceKind: 1 | 2 } | null {
  if (route === API_ROUTES.sendRetrieve) {
    return { locator: parseSendRetrieveRequestJson(text).locator, resourceKind: 1 };
  }
  if (route === API_ROUTES.sendStatus || route === API_ROUTES.sendRevoke) {
    return { locator: parseSendManageRequestJson(text).locator, resourceKind: 1 };
  }
  if (route === API_ROUTES.sendShorten) {
    return { locator: parseSendShortenRequestJson(text).locator, resourceKind: 1 };
  }
  if (route === API_ROUTES.requestSchema) {
    return { locator: parseRequestWriteRequestJson(text).locator, resourceKind: 2 };
  }
  if (route === API_ROUTES.requestSubmit) {
    return { locator: parseRequestSubmitRequestJson(text).locator, resourceKind: 2 };
  }
  if (route === API_ROUTES.requestStatus || route === API_ROUTES.requestPickup || route === API_ROUTES.requestRevoke) {
    return { locator: parseRequestOwnerRequestJson(text).locator, resourceKind: 2 };
  }
  if (route === API_ROUTES.requestShorten) {
    return { locator: parseRequestShortenRequestJson(text).locator, resourceKind: 2 };
  }
  return null;
}

export async function locatorLimitKey(
  rateLimitKey: Uint8Array,
  resourceKind: 1 | 2,
  locator: string
): Promise<string> {
  return blindedLocator(rateLimitKey, resourceKind, decodeCanonicalBase64Url(locator, 16, "locator"));
}

export async function locatorLimitAllows(
  limiter: EdgeRateLimiter,
  rateLimitKey: Uint8Array,
  resourceKind: 1 | 2,
  locator: string
): Promise<boolean> {
  return edgeLimitAllows(limiter, await locatorLimitKey(rateLimitKey, resourceKind, locator));
}

async function passLocatorLimit(
  environment: WorkerEnv,
  checked: CheckedWorkerEnvironment,
  route: string,
  text: string
): Promise<boolean> {
  const bearer = bearerLocator(route, text);
  if (bearer === null) {
    return true;
  }
  return locatorLimitAllows(
    environment.LOCATOR_RATE_LIMITER,
    checked.rateLimitKey,
    bearer.resourceKind,
    bearer.locator
  );
}

function parseIpv4(value: string): readonly number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const output: number[] = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (octet > 255) {
      return null;
    }
    output.push(octet);
  }
  return output;
}

function parseIpv6Side(value: string): readonly number[] | null {
  if (value === "") {
    return [];
  }
  const parts = value.split(":");
  const output: number[] = [];
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index] ?? "";
    if (part.includes(".")) {
      if (index !== parts.length - 1) {
        return null;
      }
      const ipv4 = parseIpv4(part);
      if (ipv4 === null) {
        return null;
      }
      output.push((ipv4[0] ?? 0) * 256 + (ipv4[1] ?? 0), (ipv4[2] ?? 0) * 256 + (ipv4[3] ?? 0));
    } else {
      if (!/^[0-9A-Fa-f]{1,4}$/u.test(part)) {
        return null;
      }
      output.push(Number.parseInt(part, 16));
    }
  }
  return output;
}

export function normalizeClientNetwork(value: string | null): string {
  if (value === null) {
    return "unknown";
  }
  const ipv4 = parseIpv4(value);
  if (ipv4 !== null) {
    return `ipv4:${ipv4[0]}.${ipv4[1]}.${ipv4[2]}.0/24`;
  }
  if (value.includes("%") || value.split("::").length > 2) {
    return "unknown";
  }
  const halves = value.split("::");
  const left = parseIpv6Side(halves[0] ?? "");
  const right = parseIpv6Side(halves[1] ?? "");
  if (left === null || right === null) {
    return "unknown";
  }
  let groups: readonly number[];
  if (halves.length === 1) {
    if (left.length !== 8) {
      return "unknown";
    }
    groups = left;
  } else {
    const missing = 8 - left.length - right.length;
    if (missing < 1) {
      return "unknown";
    }
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  }
  return `ipv6:${groups.slice(0, 4).map((group) => group.toString(16).padStart(4, "0")).join(":")}::/64`;
}

async function consumePermit(request: Request, environment: WorkerEnv): Promise<Response | null> {
  const seed = permitSeedFromCookie(request);
  if (seed === null) {
    return apiError("creation_permit_required", 403);
  }
  const permit = await permitFromSeed(seed);
  const response = await invoke(stubFor(environment.CREATE_PERMIT_OBJECTS, permit.locator), "consume", permit);
  return response.ok ? null : response;
}

function validateRouteBody(route: string, text: string): boolean {
  if (route === API_ROUTES.createPermit) {
    parseCreatePermitRequestJson(text);
  } else if (route === API_ROUTES.createPermitStatus) {
    parseEmptyRequestJson(text);
  } else if (route === API_ROUTES.sendCreate) {
    parseSendCreateRequestJson(text);
  } else if (route === API_ROUTES.sendRetrieve) {
    parseSendRetrieveRequestJson(text);
  } else if (route === API_ROUTES.sendStatus || route === API_ROUTES.sendRevoke) {
    parseSendManageRequestJson(text);
  } else if (route === API_ROUTES.sendShorten) {
    parseSendShortenRequestJson(text);
  } else if (route === API_ROUTES.requestCreate) {
    parseRequestCreateRequestJson(text);
  } else if (route === API_ROUTES.requestSchema) {
    parseRequestWriteRequestJson(text);
  } else if (route === API_ROUTES.requestSubmit) {
    parseRequestSubmitRequestJson(text);
  } else if (route === API_ROUTES.requestStatus || route === API_ROUTES.requestPickup || route === API_ROUTES.requestRevoke) {
    parseRequestOwnerRequestJson(text);
  } else if (route === API_ROUTES.requestShorten) {
    parseRequestShortenRequestJson(text);
  } else {
    return false;
  }
  return true;
}

async function handleCreatePermit(
  text: string,
  environment: WorkerEnv,
  checked: CheckedWorkerEnvironment,
  siteverifyFetch: typeof fetch
): Promise<{ readonly response: Response; readonly cookie?: string }> {
  const input = parseCreatePermitRequestJson(text);
  const gate = await verifyTurnstile(checked, input.requestId, input.turnstileResponse, siteverifyFetch);
  if (gate.kind === "failed") {
    return { response: apiError("gate_failed", 403) };
  }
  if (gate.kind === "unavailable") {
    return { response: apiError("gate_unavailable", 503) };
  }
  const material = await derivePermitMaterial(checked.permitIssuanceKey, decodeUuid(input.requestId));
  const body = {
    locator: encodeBase64Url(material.locator),
    permitExpiresAt: gate.permitExpiresAt,
    token: encodeBase64Url(material.token)
  };
  const response = await invokeWithRetry(stubFor(environment.CREATE_PERMIT_OBJECTS, body.locator), "init", body);
  if (!response.ok) {
    return { cookie: expiredPermitCookie(), response };
  }
  return { cookie: permitCookie(encodeBase64Url(material.permitSeed)), response };
}

async function handlePermitStatus(request: Request, text: string, environment: WorkerEnv): Promise<Response> {
  parseEmptyRequestJson(text);
  const seed = permitSeedFromCookie(request);
  if (seed === null) {
    return apiError("creation_permit_required", 403);
  }
  const permit = await permitFromSeed(seed);
  return invoke(stubFor(environment.CREATE_PERMIT_OBJECTS, permit.locator), "status", permit);
}

async function handleSend(
  route: string,
  request: Request,
  text: string,
  environment: WorkerEnv
): Promise<{ readonly consumedPermit: boolean; readonly response: Response }> {
  if (route === API_ROUTES.sendCreate) {
    const input = parseSendCreateRequestJson(text);
    if (!validateCreationTimes(input, unixSeconds())) {
      return { consumedPermit: false, response: apiError("invalid_request", 400) };
    }
    let permitFailure: Response | null;
    try {
      permitFailure = await consumePermit(request, environment);
    } catch {
      return {
        consumedPermit: permitSeedFromCookie(request) !== null,
        response: apiError("internal_error", 500)
      };
    }
    if (permitFailure !== null) {
      return { consumedPermit: permitSeedFromCookie(request) !== null, response: permitFailure };
    }
    try {
      const response = await invokeWithRetry(stubFor(environment.SEND_OBJECTS, input.locator), "init", input);
      return { consumedPermit: true, response };
    } catch {
      return { consumedPermit: true, response: apiError("internal_error", 500) };
    }
  }

  if (route === API_ROUTES.sendRetrieve) {
    const input = parseSendRetrieveRequestJson(text);
    return {
      consumedPermit: false,
      response: await invoke(stubFor(environment.SEND_OBJECTS, input.locator), "retrieve", input)
    };
  }

  if (route === API_ROUTES.sendStatus || route === API_ROUTES.sendRevoke) {
    const input = parseSendManageRequestJson(text);
    return {
      consumedPermit: false,
      response: await invoke(
        stubFor(environment.SEND_OBJECTS, input.locator),
        route === API_ROUTES.sendStatus ? "status" : "revoke",
        input
      )
    };
  }

  const input = parseSendShortenRequestJson(text);
  return {
    consumedPermit: false,
    response: await invoke(stubFor(environment.SEND_OBJECTS, input.locator), "shorten", input)
  };
}

async function handleRequest(
  route: string,
  request: Request,
  text: string,
  environment: WorkerEnv
): Promise<{ readonly consumedPermit: boolean; readonly response: Response }> {
  if (route === API_ROUTES.requestCreate) {
    const input = parseRequestCreateRequestJson(text);
    if (!validateCreationTimes(input, unixSeconds())) {
      return { consumedPermit: false, response: apiError("invalid_request", 400) };
    }
    let permitFailure: Response | null;
    try {
      permitFailure = await consumePermit(request, environment);
    } catch {
      return {
        consumedPermit: permitSeedFromCookie(request) !== null,
        response: apiError("internal_error", 500)
      };
    }
    if (permitFailure !== null) {
      return { consumedPermit: permitSeedFromCookie(request) !== null, response: permitFailure };
    }
    try {
      const response = await invokeWithRetry(stubFor(environment.REQUEST_OBJECTS, input.locator), "init", input);
      return { consumedPermit: true, response };
    } catch {
      return { consumedPermit: true, response: apiError("internal_error", 500) };
    }
  }

  if (route === API_ROUTES.requestSchema) {
    const input = parseRequestWriteRequestJson(text);
    return {
      consumedPermit: false,
      response: await invoke(stubFor(environment.REQUEST_OBJECTS, input.locator), "schema", input)
    };
  }

  if (route === API_ROUTES.requestSubmit) {
    const input = parseRequestSubmitRequestJson(text);
    const internal = { ...input, attemptId: randomBase64Url(16) };
    return {
      consumedPermit: false,
      response: await invokeWithRetry(stubFor(environment.REQUEST_OBJECTS, input.locator), "submit", internal)
    };
  }

  if (route === API_ROUTES.requestStatus || route === API_ROUTES.requestPickup || route === API_ROUTES.requestRevoke) {
    const input = parseRequestOwnerRequestJson(text);
    const action = route === API_ROUTES.requestStatus ? "status" : route === API_ROUTES.requestPickup ? "pickup" : "revoke";
    return {
      consumedPermit: false,
      response: await invoke(stubFor(environment.REQUEST_OBJECTS, input.locator), action, input)
    };
  }

  const input = parseRequestShortenRequestJson(text);
  return {
    consumedPermit: false,
    response: await invoke(stubFor(environment.REQUEST_OBJECTS, input.locator), "shorten", input)
  };
}

export async function handleApiRequest(
  request: Request,
  environment: WorkerEnv,
  siteverifyFetch: typeof fetch
): Promise<Response> {
  let checked: CheckedWorkerEnvironment;
  try {
    checked = checkWorkerEnvironment(environment);
  } catch {
    return finalizeApiResponse(apiError("internal_error", 500), environment.EXPECTED_ORIGIN);
  }
  const origin = request.headers.get("Origin");
  if (origin !== checked.expectedOrigin) {
    return finalizeApiResponse(apiError("forbidden", 403), checked.expectedOrigin);
  }
  if (request.method === "OPTIONS") {
    return finalizeApiResponse(new Response(null, {
      headers: {
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS"
      },
      status: 204
    }), checked.expectedOrigin);
  }
  if (request.method !== "POST") {
    return finalizeApiResponse(apiError("invalid_request", 400), checked.expectedOrigin);
  }
  const route = new URL(request.url).pathname;
  if (MUTATING_ROUTES.has(route)) {
    const fetchSite = request.headers.get("Sec-Fetch-Site");
    if (fetchSite !== null && fetchSite !== "same-origin") {
      return finalizeApiResponse(apiError("forbidden", 403), checked.expectedOrigin);
    }
  }

  let text: string;
  try {
    text = await readBody(request, isEnvelopeRoute(route) ? MAX_ENVELOPE_BODY_BYTES : MAX_SMALL_BODY_BYTES);
    if (!validateRouteBody(route, text)) {
      return finalizeApiResponse(apiError("invalid_request", 400), checked.expectedOrigin);
    }
  } catch {
    return finalizeApiResponse(apiError("invalid_request", 400), checked.expectedOrigin);
  }

  if (!(await passEdgeLimit(environment, request, route))) {
    return finalizeApiResponse(rateLimited(), checked.expectedOrigin);
  }
  if (!(await passLocatorLimit(environment, checked, route, text))) {
    return finalizeApiResponse(rateLimited(), checked.expectedOrigin);
  }

  try {
    if (route === API_ROUTES.createPermit) {
      const result = await handleCreatePermit(text, environment, checked, siteverifyFetch);
      return finalizeApiResponse(result.response, checked.expectedOrigin, result.cookie);
    }
    if (route === API_ROUTES.createPermitStatus) {
      return finalizeApiResponse(await handlePermitStatus(request, text, environment), checked.expectedOrigin);
    }
    if (
      route === API_ROUTES.sendCreate ||
      route === API_ROUTES.sendRetrieve ||
      route === API_ROUTES.sendStatus ||
      route === API_ROUTES.sendRevoke ||
      route === API_ROUTES.sendShorten
    ) {
      const result = await handleSend(route, request, text, environment);
      return finalizeApiResponse(
        result.response,
        checked.expectedOrigin,
        result.consumedPermit ? expiredPermitCookie() : undefined
      );
    }
    if (
      route === API_ROUTES.requestCreate ||
      route === API_ROUTES.requestSchema ||
      route === API_ROUTES.requestSubmit ||
      route === API_ROUTES.requestStatus ||
      route === API_ROUTES.requestPickup ||
      route === API_ROUTES.requestRevoke ||
      route === API_ROUTES.requestShorten
    ) {
      const result = await handleRequest(route, request, text, environment);
      return finalizeApiResponse(
        result.response,
        checked.expectedOrigin,
        result.consumedPermit ? expiredPermitCookie() : undefined
      );
    }
    return finalizeApiResponse(apiError("invalid_request", 400), checked.expectedOrigin);
  } catch {
    return finalizeApiResponse(apiError("internal_error", 500), checked.expectedOrigin);
  }
}

export default {
  async fetch(request: Request, environment: WorkerEnv): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    if (pathname.startsWith("/api/")) {
      return handleApiRequest(request, environment, fetch);
    }
    return secureAssetResponse(await environment.ASSETS.fetch(request), pathname === "/gate");
  }
} satisfies ExportedHandler<WorkerEnv>;
