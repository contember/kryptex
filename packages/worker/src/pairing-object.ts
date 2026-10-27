import { decodeUserCode } from "@kryptex/contracts/api";
import { PAIRING_TTL_SECONDS } from "@kryptex/contracts/protocol";
import { authenticate } from "./auth.js";
import { capabilityTag, CREATE_PERMIT_V2_TTL_SECONDS, pairingLocator, unixSeconds } from "./core.js";
import { checkWorkerEnvironment, type CheckedWorkerEnvironment, type WorkerEnv } from "./env.js";
import { apiError, jsonResponse, rateLimited, unavailable } from "./http.js";
import { RECORD_KEY, type PairingRecord } from "./state.js";
import { decodeCanonicalBase64Url, exactObject, integerProperty, parseJson, stringProperty } from "./strict.js";

interface PairingCapabilityInput {
  readonly pollToken: string;
  readonly userCode: string;
}

interface PairingApproveInput {
  readonly keyId: string;
  readonly permitExpiresAt: number;
  readonly requestId: string;
}

function parseCapabilityInput(text: string, context: string): PairingCapabilityInput {
  const object = exactObject(parseJson(text), ["pollToken", "userCode"], context);
  const pollToken = stringProperty(object, "pollToken", context);
  const userCode = stringProperty(object, "userCode", context);
  decodeCanonicalBase64Url(pollToken, 32, "poll token");
  decodeUserCode(userCode);
  return { pollToken, userCode };
}

function parseApproveInput(text: string): PairingApproveInput {
  const object = exactObject(parseJson(text), ["keyId", "permitExpiresAt", "requestId"], "pairing approval");
  const keyId = stringProperty(object, "keyId", "pairing approval");
  const requestId = stringProperty(object, "requestId", "pairing approval");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) {
    throw new Error("pairing approval key ID is invalid");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId)) {
    throw new Error("pairing approval request ID is invalid");
  }
  return { keyId, permitExpiresAt: integerProperty(object, "permitExpiresAt", "pairing approval"), requestId };
}

function decodeCapability(input: PairingCapabilityInput): { readonly locator: Uint8Array; readonly token: Uint8Array } {
  return {
    locator: pairingLocator(decodeUserCode(input.userCode)),
    token: decodeCanonicalBase64Url(input.pollToken, 32, "poll token")
  };
}

/** One pairing per user code. It never stores the permit seed, only what the Worker needs to derive it again. */
export class PairingDurableObject {
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
      return this.#initialize(parseCapabilityInput(text, "pairing initialization"));
    }
    if (pathname === "/approve") {
      return this.#approve(parseApproveInput(text));
    }
    if (pathname === "/redeem") {
      return this.#redeem(parseCapabilityInput(text, "pairing redemption"));
    }
    return apiError("invalid_request", 400);
  }

  async alarm(): Promise<void> {
    await this.#context.storage.deleteAll();
  }

  async #initialize(input: PairingCapabilityInput): Promise<Response> {
    const capability = decodeCapability(input);
    const tag = await capabilityTag(this.#environment().activeCapabilityKey, 4, 4, capability.locator, capability.token);
    const created = await this.#context.storage.transaction(async (transaction) => {
      if (await transaction.get<PairingRecord>(RECORD_KEY) !== undefined) {
        return null;
      }
      const record: PairingRecord = {
        approval: null,
        authKeyId: this.#environment().activeCapabilityKeyId,
        generation: 1,
        kind: "pairing",
        pairingExpiresAt: unixSeconds() + PAIRING_TTL_SECONDS,
        tag
      };
      await transaction.put(RECORD_KEY, record);
      await transaction.setAlarm(record.pairingExpiresAt * 1_000);
      return record;
    });
    if (created === null) {
      return apiError("invalid_request", 409);
    }
    return jsonResponse({ pairingExpiresAt: created.pairingExpiresAt, serverTime: unixSeconds(), userCode: input.userCode });
  }

  async #approve(input: PairingApproveInput): Promise<Response> {
    const approved = await this.#context.storage.transaction(async (transaction) => {
      const now = unixSeconds();
      const current = await transaction.get<PairingRecord>(RECORD_KEY);
      if (current === undefined) {
        return false;
      }
      if (current.approval !== null) {
        return current.approval.requestId === input.requestId && current.approval.permitExpiresAt > now;
      }
      if (
        current.pairingExpiresAt <= now ||
        input.permitExpiresAt <= now ||
        input.permitExpiresAt > now + CREATE_PERMIT_V2_TTL_SECONDS
      ) {
        return false;
      }
      const record: PairingRecord = { ...current, approval: input, generation: current.generation + 1 };
      await transaction.put(RECORD_KEY, record);
      await transaction.setAlarm(Math.max(current.pairingExpiresAt, input.permitExpiresAt) * 1_000);
      return true;
    });
    return approved ? jsonResponse({ state: "approved" }) : unavailable();
  }

  async #redeem(input: PairingCapabilityInput): Promise<Response> {
    const authentication = await authenticate(this.#context.storage, this.#environment(), {
      capabilityKind: 4,
      ...decodeCapability(input),
      resourceKind: 4
    });
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const now = unixSeconds();
    const record = this.#context.storage.kv.get<PairingRecord>(RECORD_KEY);
    if (record?.tag !== authentication.snapshot.tag) {
      return unavailable();
    }
    if (record.approval === null) {
      return record.pairingExpiresAt > now
        ? jsonResponse({ pairingExpiresAt: record.pairingExpiresAt, state: "pending" })
        : unavailable();
    }
    return record.approval.permitExpiresAt > now
      ? jsonResponse({ ...record.approval, state: "approved" })
      : unavailable();
  }
}
