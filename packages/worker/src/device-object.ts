import {
  DEVICE_GRANT_DAYS,
  DEVICE_PERMIT_TTL_SECONDS,
  DEVICE_QUOTA_PER_DAY,
  DEVICE_QUOTA_WINDOW_HOURS
} from "@kryptex/contracts/protocol";
import { authenticate } from "./auth.js";
import { unixSeconds } from "./core.js";
import { checkWorkerEnvironment, type CheckedWorkerEnvironment, type WorkerEnv } from "./env.js";
import { apiError, jsonResponse, rateLimited, unavailable } from "./http.js";
import {
  RECORD_KEY,
  spentRequestKey,
  type CapabilitySnapshot,
  type DeviceMint,
  type DeviceRecord,
  type HourlyMintCount
} from "./state.js";
import { decodeCanonicalBase64Url, exactObject, integerProperty, parseJson, property, stringProperty } from "./strict.js";

const SECONDS_PER_HOUR = 3_600;
const MAX_GRANT_SECONDS = Math.max(...DEVICE_GRANT_DAYS) * 86_400;

interface DeviceInitInput {
  readonly deviceTag: string;
  readonly expiresAt: number;
  readonly keyId: string;
  readonly manageTag: string;
}

interface DeviceCapabilityInput {
  readonly capability: "device" | "manage";
  readonly deviceLocator: string;
  readonly token: string;
}

interface DeviceMintInput {
  readonly deviceLocator: string;
  readonly deviceToken: string;
  readonly requestId: string;
}

type MintResult =
  | { readonly kind: "minted"; readonly keyId: string; readonly mintedAt: number }
  | { readonly kind: "quota_exhausted" }
  | { readonly kind: "spent" }
  | { readonly kind: "unavailable" };

function keyIdProperty(object: object, key: string, context: string): string {
  const value = stringProperty(object, key, context);
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(value)) {
    throw new Error(`${context}.${key} is invalid`);
  }
  return value;
}

function base64UrlProperty(object: object, key: string, length: number, context: string): string {
  const value = stringProperty(object, key, context);
  decodeCanonicalBase64Url(value, length, `${context}.${key}`);
  return value;
}

function parseInitInput(text: string): DeviceInitInput {
  const context = "device initialization";
  const object = exactObject(parseJson(text), ["deviceTag", "expiresAt", "keyId", "manageTag"], context);
  return {
    deviceTag: base64UrlProperty(object, "deviceTag", 32, context),
    expiresAt: integerProperty(object, "expiresAt", context),
    keyId: keyIdProperty(object, "keyId", context),
    manageTag: base64UrlProperty(object, "manageTag", 32, context)
  };
}

function parseCapabilityInput(text: string): DeviceCapabilityInput {
  const context = "device access";
  const object = exactObject(parseJson(text), ["capability", "deviceLocator", "token"], context);
  const capability = property(object, "capability", context);
  if (capability !== "device" && capability !== "manage") {
    throw new Error("device access capability is invalid");
  }
  return {
    capability,
    deviceLocator: base64UrlProperty(object, "deviceLocator", 16, context),
    token: base64UrlProperty(object, "token", 32, context)
  };
}

function parseMintInput(text: string): DeviceMintInput {
  const context = "device permit mint";
  const object = exactObject(parseJson(text), ["deviceLocator", "deviceToken", "requestId"], context);
  const requestId = stringProperty(object, "requestId", context);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId)) {
    throw new Error("device permit mint request ID is invalid");
  }
  return {
    deviceLocator: base64UrlProperty(object, "deviceLocator", 16, context),
    deviceToken: base64UrlProperty(object, "deviceToken", 32, context),
    requestId
  };
}

function currentHour(now: number): number {
  return Math.floor(now / SECONDS_PER_HOUR);
}

/** Counts for the last 24 whole UTC hours, oldest first, ending with the current hour. */
function hourlyWindow(counts: readonly HourlyMintCount[], now: number): readonly number[] {
  const hour = currentHour(now);
  return Array.from({ length: DEVICE_QUOTA_WINDOW_HOURS }, (_, index) => {
    const slot = hour - DEVICE_QUOTA_WINDOW_HOURS + 1 + index;
    return counts.find((entry) => entry.hour === slot)?.count ?? 0;
  });
}

function windowTotal(counts: readonly HourlyMintCount[], now: number): number {
  return hourlyWindow(counts, now).reduce((total, count) => total + count, 0);
}

function charged(counts: readonly HourlyMintCount[], now: number): readonly HourlyMintCount[] {
  const hour = currentHour(now);
  const kept = counts.filter((entry) => entry.hour > hour - DEVICE_QUOTA_WINDOW_HOURS && entry.hour !== hour);
  const current = counts.find((entry) => entry.hour === hour)?.count ?? 0;
  return [...kept, { count: current + 1, hour }];
}

function isRecentMint(mint: DeviceMint, now: number): boolean {
  return mint.mintedAt + DEVICE_PERMIT_TTL_SECONDS > now;
}

/** The next alarm drops expired mint times, or deletes the grant at its expiry. */
function nextAlarmSeconds(record: DeviceRecord): number {
  return Math.min(record.expiresAt, ...record.recentMints.map((mint) => mint.mintedAt + DEVICE_PERMIT_TTL_SECONDS));
}

function snapshotMatches(record: DeviceRecord | undefined, snapshot: CapabilitySnapshot, tag: "device" | "manage"): record is DeviceRecord {
  return record?.generation === snapshot.generation &&
    record.authKeyId === snapshot.keyId &&
    (tag === "device" ? record.deviceTag : record.manageTag) === snapshot.tag;
}

/** One device grant per device locator. It never records which resource a permit created. */
export class DeviceDurableObject {
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
    if (pathname === "/mint") {
      return this.#mint(parseMintInput(text));
    }
    if (pathname === "/status") {
      return this.#status(parseCapabilityInput(text));
    }
    if (pathname === "/revoke") {
      return this.#revoke(parseCapabilityInput(text));
    }
    return apiError("invalid_request", 400);
  }

  async alarm(): Promise<void> {
    const storage = this.#context.storage;
    const now = unixSeconds();
    const record = await storage.get<DeviceRecord>(RECORD_KEY);
    if (record === undefined || record.expiresAt <= now) {
      await storage.deleteAll();
      return;
    }
    await storage.transaction(async (transaction) => {
      const current = await transaction.get<DeviceRecord>(RECORD_KEY);
      if (current === undefined) {
        return;
      }
      const pruned = await this.#pruneMints(transaction, current, unixSeconds());
      await transaction.put(RECORD_KEY, pruned);
      await transaction.setAlarm(nextAlarmSeconds(pruned) * 1_000);
    });
  }

  /** Moves request IDs past the device-permit lifetime to spent keys, which keep no time. */
  async #pruneMints(transaction: DurableObjectTransaction, record: DeviceRecord, now: number): Promise<DeviceRecord> {
    const expired = record.recentMints.filter((mint) => !isRecentMint(mint, now));
    for (const mint of expired) {
      await transaction.put(spentRequestKey(mint.requestId), true);
    }
    return expired.length === 0 ? record : { ...record, recentMints: record.recentMints.filter((mint) => isRecentMint(mint, now)) };
  }

  async #initialize(input: DeviceInitInput): Promise<Response> {
    const initialized = await this.#context.storage.transaction(async (transaction) => {
      const now = unixSeconds();
      const current = await transaction.get<DeviceRecord>(RECORD_KEY);
      if (current !== undefined) {
        return current.deviceTag === input.deviceTag &&
          current.manageTag === input.manageTag &&
          current.authKeyId === input.keyId &&
          current.expiresAt === input.expiresAt;
      }
      if (input.expiresAt <= now || input.expiresAt > now + MAX_GRANT_SECONDS) {
        return false;
      }
      const record: DeviceRecord = {
        authKeyId: input.keyId,
        deviceTag: input.deviceTag,
        expiresAt: input.expiresAt,
        generation: 1,
        hourlyMints: [],
        kind: "device",
        manageTag: input.manageTag,
        recentMints: [],
        revoked: false
      };
      await transaction.put(RECORD_KEY, record);
      await transaction.setAlarm(record.expiresAt * 1_000);
      return true;
    });
    return initialized ? jsonResponse({ state: "initialized" }) : unavailable();
  }

  async #authenticate(capability: "device" | "manage", deviceLocator: string, token: string): Promise<
    | { readonly kind: "authorized"; readonly snapshot: CapabilitySnapshot }
    | { readonly kind: "failed"; readonly response: Response }
  > {
    const authentication = await authenticate(this.#context.storage, this.#environment(), {
      capabilityKind: capability === "device" ? 5 : 6,
      locator: decodeCanonicalBase64Url(deviceLocator, 16, "device locator"),
      resourceKind: 5,
      token: decodeCanonicalBase64Url(token, 32, "device capability token")
    });
    if (authentication.kind === "rate_limited") {
      return { kind: "failed", response: rateLimited() };
    }
    if (authentication.kind === "unavailable") {
      return { kind: "failed", response: unavailable() };
    }
    return { kind: "authorized", snapshot: authentication.snapshot };
  }

  async #mint(input: DeviceMintInput): Promise<Response> {
    const authorized = await this.#authenticate("device", input.deviceLocator, input.deviceToken);
    if (authorized.kind === "failed") {
      return authorized.response;
    }
    const activeKeyId = this.#environment().activePermitIssuanceKeyId;
    const result = await this.#context.storage.transaction<MintResult>(async (transaction) => {
      const now = unixSeconds();
      const current = await transaction.get<DeviceRecord>(RECORD_KEY);
      if (!snapshotMatches(current, authorized.snapshot, "device") || current.revoked || current.expiresAt <= now) {
        return { kind: "unavailable" };
      }
      const record = await this.#pruneMints(transaction, current, now);
      if (record !== current) {
        await transaction.put(RECORD_KEY, record);
      }
      const replay = record.recentMints.find((mint) => mint.requestId === input.requestId);
      if (replay !== undefined) {
        return { keyId: replay.keyId, kind: "minted", mintedAt: replay.mintedAt };
      }
      if (await transaction.get(spentRequestKey(input.requestId)) !== undefined) {
        return { kind: "spent" };
      }
      if (windowTotal(record.hourlyMints, now) >= DEVICE_QUOTA_PER_DAY) {
        return { kind: "quota_exhausted" };
      }
      const mint: DeviceMint = { keyId: activeKeyId, mintedAt: now, requestId: input.requestId };
      const updated: DeviceRecord = {
        ...record,
        hourlyMints: charged(record.hourlyMints, now),
        recentMints: [...record.recentMints, mint]
      };
      await transaction.put(RECORD_KEY, updated);
      await transaction.setAlarm(nextAlarmSeconds(updated) * 1_000);
      return { keyId: mint.keyId, kind: "minted", mintedAt: mint.mintedAt };
    });
    if (result.kind === "quota_exhausted") {
      return apiError("quota_exhausted", 429);
    }
    if (result.kind === "unavailable") {
      return unavailable();
    }
    if (result.kind === "spent") {
      // The caller already proved the device token, so this reveals nothing; it mints again with a fresh ID.
      return apiError("creation_permit_required", 403);
    }
    return jsonResponse({ keyId: result.keyId, mintedAt: result.mintedAt });
  }

  async #status(input: DeviceCapabilityInput): Promise<Response> {
    const authorized = await this.#authenticate(input.capability, input.deviceLocator, input.token);
    if (authorized.kind === "failed") {
      return authorized.response;
    }
    const now = unixSeconds();
    const record = this.#context.storage.kv.get<DeviceRecord>(RECORD_KEY);
    if (!snapshotMatches(record, authorized.snapshot, input.capability) || record.expiresAt <= now) {
      return unavailable();
    }
    const hourlyMints = hourlyWindow(record.hourlyMints, now);
    const used = hourlyMints.reduce((total, count) => total + count, 0);
    return jsonResponse({
      expiresAt: record.expiresAt,
      hourlyMints,
      quotaRemaining: Math.max(0, DEVICE_QUOTA_PER_DAY - used),
      state: record.revoked ? "revoked" : "active"
    });
  }

  async #revoke(input: DeviceCapabilityInput): Promise<Response> {
    const authorized = await this.#authenticate(input.capability, input.deviceLocator, input.token);
    if (authorized.kind === "failed") {
      return authorized.response;
    }
    const storage = this.#context.storage;
    const revoked = storage.transactionSync(() => {
      const current = storage.kv.get<DeviceRecord>(RECORD_KEY);
      if (!snapshotMatches(current, authorized.snapshot, input.capability) || current.expiresAt <= unixSeconds()) {
        return false;
      }
      if (!current.revoked) {
        // A new generation fails any mint whose authentication finished before the revocation.
        storage.kv.put<DeviceRecord>(RECORD_KEY, { ...current, generation: current.generation + 1, revoked: true });
      }
      return true;
    });
    return revoked ? jsonResponse({ state: "revoked" }) : unavailable();
  }
}
