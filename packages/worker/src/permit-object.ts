import { authenticate } from "./auth.js";
import { capabilityTag, unixSeconds } from "./core.js";
import { checkWorkerEnvironment, type CheckedWorkerEnvironment, type WorkerEnv } from "./env.js";
import { apiError, jsonResponse, rateLimited } from "./http.js";
import { decodeCanonicalBase64Url, exactObject, integerProperty, parseJson, stringProperty } from "./strict.js";
import { RECORD_KEY, type CapabilitySnapshot, type PermitRecord } from "./state.js";

interface PermitInput {
  readonly locator: string;
  readonly token: string;
}

interface PermitInitializationInput extends PermitInput {
  readonly permitExpiresAt: number;
}

export function commitPermitOperation(
  storage: DurableObjectStorage,
  snapshot: CapabilitySnapshot,
  consume: boolean,
  clock: () => number
): PermitRecord | undefined {
  return storage.transactionSync(() => {
    const now = unixSeconds(clock());
    const current = storage.kv.get<PermitRecord>(RECORD_KEY);
    if (
      current?.generation !== snapshot.generation ||
      current.authKeyId !== snapshot.keyId ||
      current.tag !== snapshot.tag ||
      current.state !== "unused" ||
      current.permitExpiresAt <= now
    ) {
      return undefined;
    }
    if (!consume) {
      return current;
    }
    const consumed: PermitRecord = { ...current, generation: current.generation + 1, state: "consumed" };
    storage.kv.put(RECORD_KEY, consumed);
    return consumed;
  });
}

function parsePermitInput(text: string): PermitInput {
  const object = exactObject(parseJson(text), ["locator", "token"], "permit operation");
  const locator = stringProperty(object, "locator", "permit operation");
  const token = stringProperty(object, "token", "permit operation");
  decodeCanonicalBase64Url(locator, 16, "permit locator");
  decodeCanonicalBase64Url(token, 32, "permit token");
  return { locator, token };
}

function parsePermitInitializationInput(text: string): PermitInitializationInput {
  const object = exactObject(parseJson(text), ["locator", "permitExpiresAt", "token"], "permit initialization");
  const locator = stringProperty(object, "locator", "permit initialization");
  const token = stringProperty(object, "token", "permit initialization");
  decodeCanonicalBase64Url(locator, 16, "permit locator");
  decodeCanonicalBase64Url(token, 32, "permit token");
  return {
    locator,
    permitExpiresAt: integerProperty(object, "permitExpiresAt", "permit initialization"),
    token
  };
}

export class CreatePermitDurableObject {
  readonly #context: DurableObjectState;
  readonly #rawEnvironment: WorkerEnv;
  #checkedEnvironment: CheckedWorkerEnvironment | undefined;

  constructor(context: DurableObjectState, environment: WorkerEnv) {
    this.#context = context;
    this.#rawEnvironment = environment;
  }

  #environment(): CheckedWorkerEnvironment {
    this.#checkedEnvironment ??= checkWorkerEnvironment(this.#rawEnvironment);
    return this.#checkedEnvironment;
  }

  async fetch(request: Request): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    const text = await request.text();
    if (pathname === "/init") {
      return this.#initialize(parsePermitInitializationInput(text));
    }
    const input = parsePermitInput(text);
    if (pathname === "/status") {
      return this.#operate(input, false);
    }
    if (pathname === "/consume") {
      return this.#operate(input, true);
    }
    return apiError("invalid_request", 400);
  }

  async alarm(): Promise<void> {
    await this.#context.storage.deleteAll();
  }

  async #initialize(input: PermitInitializationInput): Promise<Response> {
    const locator = decodeCanonicalBase64Url(input.locator, 16, "permit locator");
    const token = decodeCanonicalBase64Url(input.token, 32, "permit token");
    const tag = await capabilityTag(this.#environment().activeCapabilityKey, 3, 3, locator, token);
    const result = await this.#context.storage.transaction(async (transaction) => {
      const now = unixSeconds();
      const current = await transaction.get<PermitRecord>(RECORD_KEY);
      if (current !== undefined) {
        if (current.tag === tag && current.state === "unused" && current.permitExpiresAt > now) {
          return { expiresAt: current.permitExpiresAt, kind: "available" };
        }
        return { kind: "unavailable" };
      }
      if (input.permitExpiresAt <= now || input.permitExpiresAt > now + 300) {
        return { kind: "unavailable" };
      }
      const permitExpiresAt = input.permitExpiresAt;
      const record: PermitRecord = {
        authKeyId: this.#environment().activeCapabilityKeyId,
        createdAt: now,
        generation: 1,
        kind: "permit",
        permitExpiresAt,
        state: "unused",
        tag
      };
      await transaction.put(RECORD_KEY, record);
      await transaction.setAlarm(permitExpiresAt * 1_000);
      return { expiresAt: permitExpiresAt, kind: "available" };
    });
    if (result.kind === "unavailable") {
      return apiError("creation_permit_required", 403);
    }
    return jsonResponse({ permitExpiresAt: result.expiresAt, serverTime: unixSeconds() });
  }

  async #operate(input: PermitInput, consume: boolean): Promise<Response> {
    const decoded = {
      locator: decodeCanonicalBase64Url(input.locator, 16, "permit locator"),
      token: decodeCanonicalBase64Url(input.token, 32, "permit token")
    };
    const authentication = await authenticate(this.#context.storage, this.#environment(), {
      capabilityKind: 3,
      locator: decoded.locator,
      resourceKind: 3,
      token: decoded.token
    });
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return apiError("creation_permit_required", 403);
    }
    const now = unixSeconds();
    const record = commitPermitOperation(this.#context.storage, authentication.snapshot, consume, Date.now);
    if (record === undefined) {
      return apiError("creation_permit_required", 403);
    }
    if (consume) {
      return jsonResponse({ state: "consumed" });
    }
    return jsonResponse({ permitExpiresAt: record.permitExpiresAt, serverTime: now, state: "unused" });
  }
}
