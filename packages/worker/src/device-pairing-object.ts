import { decodeUserCode } from "@kryptex/contracts/api";
import {
  DEVICE_PAIRING_CLAIM_RETENTION_SECONDS,
  DEVICE_PAIRING_TTL_SECONDS,
  isDeviceGrantDays,
  type DeviceGrantDays
} from "@kryptex/contracts/protocol";
import { authenticate } from "./auth.js";
import { capabilityTag, CREATE_PERMIT_V2_TTL_SECONDS, pairingLocator, unixSeconds } from "./core.js";
import { checkWorkerEnvironment, type CheckedWorkerEnvironment, type WorkerEnv } from "./env.js";
import { apiError, jsonResponse, rateLimited, unavailable } from "./http.js";
import { RECORD_KEY, type CapabilitySnapshot, type DevicePairingClaim, type DevicePairingRecord } from "./state.js";
import { decodeCanonicalBase64Url, exactObject, integerProperty, parseJson, property, stringProperty } from "./strict.js";

const SECONDS_PER_DAY = 86_400;

interface DevicePairingInitInput {
  readonly deviceLocator: string;
  readonly deviceToken: string;
  readonly maxDays: DeviceGrantDays;
  readonly userCode: string;
}

interface DevicePairingApproveInput {
  readonly claimToken: string;
  readonly keyId: string;
  readonly permitExpiresAt: number;
  readonly requestId: string;
  readonly userCode: string;
}

interface ClaimCredentialInput {
  readonly claimToken: string;
  readonly userCode: string;
}

type ClaimChoice =
  | { readonly scope: "transfer" }
  | { readonly days: DeviceGrantDays; readonly manageToken: string; readonly scope: "device" };

interface DevicePairingClaimInput extends ClaimCredentialInput {
  readonly choice: ClaimChoice;
}

interface DevicePairingRedeemInput {
  readonly deviceToken: string;
  readonly userCode: string;
}

function token(object: object, key: string, context: string): string {
  const value = stringProperty(object, key, context);
  decodeCanonicalBase64Url(value, 32, `${context}.${key}`);
  return value;
}

function userCode(object: object, context: string): string {
  const value = stringProperty(object, "userCode", context);
  decodeUserCode(value);
  return value;
}

function grantDays(object: object, key: string, context: string): DeviceGrantDays {
  const value = integerProperty(object, key, context);
  if (!isDeviceGrantDays(value)) {
    throw new Error(`${context}.${key} is not a device grant lifetime`);
  }
  return value;
}

function parseInitInput(text: string): DevicePairingInitInput {
  const context = "device pairing initialization";
  const object = exactObject(parseJson(text), ["deviceLocator", "deviceToken", "maxDays", "userCode"], context);
  const deviceLocator = stringProperty(object, "deviceLocator", context);
  decodeCanonicalBase64Url(deviceLocator, 16, `${context}.deviceLocator`);
  return {
    deviceLocator,
    deviceToken: token(object, "deviceToken", context),
    maxDays: grantDays(object, "maxDays", context),
    userCode: userCode(object, context)
  };
}

function parseApproveInput(text: string): DevicePairingApproveInput {
  const context = "device pairing approval";
  const object = exactObject(parseJson(text), ["claimToken", "keyId", "permitExpiresAt", "requestId", "userCode"], context);
  const keyId = stringProperty(object, "keyId", context);
  const requestId = stringProperty(object, "requestId", context);
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) {
    throw new Error("device pairing approval key ID is invalid");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId)) {
    throw new Error("device pairing approval request ID is invalid");
  }
  return {
    claimToken: token(object, "claimToken", context),
    keyId,
    permitExpiresAt: integerProperty(object, "permitExpiresAt", context),
    requestId,
    userCode: userCode(object, context)
  };
}

function parseClaimCredentialInput(text: string): ClaimCredentialInput {
  const context = "device claim status";
  const object = exactObject(parseJson(text), ["claimToken", "userCode"], context);
  return { claimToken: token(object, "claimToken", context), userCode: userCode(object, context) };
}

function parseClaimInput(text: string): DevicePairingClaimInput {
  const context = "device claim";
  const value = parseJson(text);
  const scope = typeof value === "object" && value !== null ? property(value, "scope", context) : undefined;
  if (scope === "transfer") {
    const object = exactObject(value, ["claimToken", "scope", "userCode"], context);
    return { choice: { scope }, claimToken: token(object, "claimToken", context), userCode: userCode(object, context) };
  }
  const object = exactObject(value, ["claimToken", "days", "manageToken", "scope", "userCode"], context);
  if (property(object, "scope", context) !== "device") {
    throw new Error("device claim scope is invalid");
  }
  return {
    choice: { days: grantDays(object, "days", context), manageToken: token(object, "manageToken", context), scope: "device" },
    claimToken: token(object, "claimToken", context),
    userCode: userCode(object, context)
  };
}

function parseRedeemInput(text: string): DevicePairingRedeemInput {
  const context = "device pairing redemption";
  const object = exactObject(parseJson(text), ["deviceToken", "userCode"], context);
  return { deviceToken: token(object, "deviceToken", context), userCode: userCode(object, context) };
}

function locatorFor(code: string): Uint8Array {
  return pairingLocator(decodeUserCode(code));
}

/** The record outlives the pairing only as long as redemption must stay repeatable. */
function retainUntil(record: DevicePairingRecord): number {
  if (record.claim === null || record.approval === null) {
    return record.pairingExpiresAt;
  }
  if (record.claim.scope === "transfer") {
    return Math.max(record.pairingExpiresAt, record.approval.permitExpiresAt);
  }
  return Math.max(record.pairingExpiresAt, record.claim.claimedAt + DEVICE_PAIRING_CLAIM_RETENTION_SECONDS);
}

function sameChoice(claim: DevicePairingClaim, choice: ClaimChoice, manageTag: string | null): boolean {
  if (claim.scope === "transfer" || choice.scope === "transfer") {
    return claim.scope === choice.scope;
  }
  return claim.days === choice.days && claim.manageTag === manageTag;
}

/** One device pairing per user code. It stores tags and the approval's request ID, never a token or a permit seed. */
export class DevicePairingDurableObject {
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
      return this.#initialize(parseInitInput(text));
    }
    if (pathname === "/approve") {
      return this.#approve(parseApproveInput(text));
    }
    if (pathname === "/claim-status") {
      return this.#claimStatus(parseClaimCredentialInput(text));
    }
    if (pathname === "/claim") {
      return this.#claim(parseClaimInput(text));
    }
    if (pathname === "/confirm") {
      exactObject(parseJson(text), [], "device claim confirmation");
      return this.#confirm();
    }
    if (pathname === "/redeem") {
      return this.#redeem(parseRedeemInput(text));
    }
    return apiError("invalid_request", 400);
  }

  async alarm(): Promise<void> {
    const record = await this.#context.storage.get<DevicePairingRecord>(RECORD_KEY);
    if (record !== undefined && retainUntil(record) > unixSeconds()) {
      await this.#context.storage.setAlarm(retainUntil(record) * 1_000);
      return;
    }
    await this.#context.storage.deleteAll();
  }

  async #initialize(input: DevicePairingInitInput): Promise<Response> {
    const environment = this.#environment();
    const deviceToken = decodeCanonicalBase64Url(input.deviceToken, 32, "device token");
    const pollTag = await capabilityTag(environment.activeCapabilityKey, 6, 5, locatorFor(input.userCode), deviceToken);
    const grantTag = await capabilityTag(
      environment.activeCapabilityKey,
      5,
      5,
      decodeCanonicalBase64Url(input.deviceLocator, 16, "device locator"),
      deviceToken
    );
    const created = await this.#context.storage.transaction(async (transaction) => {
      if (await transaction.get<DevicePairingRecord>(RECORD_KEY) !== undefined) {
        return null;
      }
      const record: DevicePairingRecord = {
        approval: null,
        authKeyId: environment.activeCapabilityKeyId,
        claim: null,
        deviceLocator: input.deviceLocator,
        generation: 1,
        grantTag,
        kind: "device_pairing",
        maxDays: input.maxDays,
        pairingExpiresAt: unixSeconds() + DEVICE_PAIRING_TTL_SECONDS,
        pollTag
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

  async #approve(input: DevicePairingApproveInput): Promise<Response> {
    const storage = this.#context.storage;
    const before = storage.kv.get<DevicePairingRecord>(RECORD_KEY);
    const key = before === undefined ? undefined : this.#environment().capabilityKeys.get(before.authKeyId);
    if (before === undefined || key === undefined) {
      return unavailable();
    }
    const claimTag = await capabilityTag(
      key,
      6,
      7,
      locatorFor(input.userCode),
      decodeCanonicalBase64Url(input.claimToken, 32, "claim token")
    );
    const pairingExpiresAt = storage.transactionSync(() => {
      const now = unixSeconds();
      const current = storage.kv.get<DevicePairingRecord>(RECORD_KEY);
      if (current?.authKeyId !== before.authKeyId || current.claim !== null || current.pairingExpiresAt <= now) {
        return null;
      }
      if (current.approval !== null && current.approval.requestId !== input.requestId) {
        return null;
      }
      if (
        current.approval === null &&
        (input.permitExpiresAt <= now || input.permitExpiresAt > now + CREATE_PERMIT_V2_TTL_SECONDS)
      ) {
        return null;
      }
      // A retry of the same approval keeps the recorded permit and only replaces the claim-token tag.
      const approval = current.approval === null
        ? { claimTag, keyId: input.keyId, permitExpiresAt: input.permitExpiresAt, requestId: input.requestId }
        : { ...current.approval, claimTag };
      storage.kv.put<DevicePairingRecord>(RECORD_KEY, { ...current, approval, generation: current.generation + 1 });
      return current.pairingExpiresAt;
    });
    return pairingExpiresAt === null ? unavailable() : jsonResponse({ pairingExpiresAt, state: "approved" });
  }

  async #authenticateClaim(input: ClaimCredentialInput): Promise<
    | { readonly kind: "authorized"; readonly record: DevicePairingRecord; readonly snapshot: CapabilitySnapshot }
    | { readonly kind: "failed"; readonly response: Response }
  > {
    const authentication = await authenticate(this.#context.storage, this.#environment(), {
      capabilityKind: 7,
      locator: locatorFor(input.userCode),
      resourceKind: 6,
      token: decodeCanonicalBase64Url(input.claimToken, 32, "claim token")
    });
    if (authentication.kind === "rate_limited") {
      return { kind: "failed", response: rateLimited() };
    }
    if (authentication.kind === "unavailable") {
      return { kind: "failed", response: unavailable() };
    }
    const record = this.#context.storage.kv.get<DevicePairingRecord>(RECORD_KEY);
    if (record?.approval?.claimTag !== authentication.snapshot.tag) {
      return { kind: "failed", response: unavailable() };
    }
    return { kind: "authorized", record, snapshot: authentication.snapshot };
  }

  async #claimStatus(input: ClaimCredentialInput): Promise<Response> {
    const authorized = await this.#authenticateClaim(input);
    if (authorized.kind === "failed") {
      return authorized.response;
    }
    const record = authorized.record;
    if (record.claim !== null || record.pairingExpiresAt <= unixSeconds()) {
      return unavailable();
    }
    return jsonResponse({ maxDays: record.maxDays, pairingExpiresAt: record.pairingExpiresAt });
  }

  async #claim(input: DevicePairingClaimInput): Promise<Response> {
    const authorized = await this.#authenticateClaim(input);
    if (authorized.kind === "failed") {
      return authorized.response;
    }
    let manageTag: string | null = null;
    if (input.choice.scope === "device") {
      const key = this.#environment().capabilityKeys.get(authorized.record.authKeyId);
      if (key === undefined) {
        return apiError("internal_error", 500);
      }
      manageTag = await capabilityTag(
        key,
        5,
        6,
        decodeCanonicalBase64Url(authorized.record.deviceLocator, 16, "device locator"),
        decodeCanonicalBase64Url(input.choice.manageToken, 32, "manage token")
      );
    }
    const storage = this.#context.storage;
    const claimed = await storage.transaction(async (transaction) => {
      const now = unixSeconds();
      const current = await transaction.get<DevicePairingRecord>(RECORD_KEY);
      if (
        current?.authKeyId !== authorized.snapshot.keyId ||
        current.approval?.claimTag !== authorized.snapshot.tag
      ) {
        return null;
      }
      if (current.claim !== null) {
        return sameChoice(current.claim, input.choice, manageTag) ? { claim: current.claim, record: current } : null;
      }
      if (current.pairingExpiresAt <= now) {
        return null;
      }
      let claim: DevicePairingClaim;
      if (input.choice.scope === "transfer") {
        claim = { claimedAt: now, scope: "transfer" };
      } else {
        if (input.choice.days > current.maxDays || manageTag === null) {
          return null;
        }
        claim = {
          claimedAt: now,
          days: input.choice.days,
          deviceExpiresAt: now + input.choice.days * SECONDS_PER_DAY,
          manageTag,
          scope: "device",
          state: "claiming"
        };
      }
      const record: DevicePairingRecord = { ...current, claim, generation: current.generation + 1 };
      await transaction.put(RECORD_KEY, record);
      await transaction.setAlarm(retainUntil(record) * 1_000);
      return { claim, record };
    });
    if (claimed === null) {
      return unavailable();
    }
    if (claimed.claim.scope === "transfer") {
      return jsonResponse({ scope: "transfer" });
    }
    return jsonResponse({
      deviceExpiresAt: claimed.claim.deviceExpiresAt,
      deviceLocator: claimed.record.deviceLocator,
      deviceTag: claimed.record.grantTag,
      keyId: claimed.record.authKeyId,
      manageTag: claimed.claim.manageTag,
      scope: "device",
      state: claimed.claim.state
    });
  }

  /** Called by the Worker only after it initialized the device object for this claim. */
  #confirm(): Response {
    const storage = this.#context.storage;
    const confirmed = storage.transactionSync(() => {
      const current = storage.kv.get<DevicePairingRecord>(RECORD_KEY);
      if (current?.claim?.scope !== "device") {
        return false;
      }
      if (current.claim.state === "claiming") {
        storage.kv.put<DevicePairingRecord>(RECORD_KEY, {
          ...current,
          claim: { ...current.claim, state: "claimed" },
          generation: current.generation + 1
        });
      }
      return true;
    });
    return confirmed ? jsonResponse({ state: "claimed" }) : unavailable();
  }

  async #redeem(input: DevicePairingRedeemInput): Promise<Response> {
    const authentication = await authenticate(this.#context.storage, this.#environment(), {
      capabilityKind: 5,
      locator: locatorFor(input.userCode),
      resourceKind: 6,
      token: decodeCanonicalBase64Url(input.deviceToken, 32, "device token")
    });
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const now = unixSeconds();
    const record = this.#context.storage.kv.get<DevicePairingRecord>(RECORD_KEY);
    if (record?.pollTag !== authentication.snapshot.tag) {
      return unavailable();
    }
    const claim = record.claim;
    if (claim === null || (claim.scope === "device" && claim.state === "claiming")) {
      return claim !== null || record.pairingExpiresAt > now
        ? jsonResponse({ pairingExpiresAt: record.pairingExpiresAt, state: "pending" })
        : unavailable();
    }
    if (claim.scope === "device") {
      return jsonResponse({ deviceExpiresAt: claim.deviceExpiresAt, state: "device" });
    }
    if (record.approval === null || record.approval.permitExpiresAt <= now) {
      return unavailable();
    }
    return jsonResponse({
      keyId: record.approval.keyId,
      permitExpiresAt: record.approval.permitExpiresAt,
      requestId: record.approval.requestId,
      state: "transfer"
    });
  }
}
