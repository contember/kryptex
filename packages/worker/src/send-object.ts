import {
  parseSendCreateRequestJson,
  parseSendManageRequestJson,
  parseSendRetrieveRequestJson,
  parseSendShortenRequestJson
} from "@kryptex/contracts/api";
import { parseKxe1Envelope } from "@kryptex/contracts/envelopes";
import { authenticate, decodeAuthInput } from "./auth.js";
import { capabilityTag, unixSeconds } from "./core.js";
import { checkWorkerEnvironment, type CheckedWorkerEnvironment, type WorkerEnv } from "./env.js";
import { binaryResponse, jsonResponse, rateLimited, unavailable } from "./http.js";
import { deleteKeys, readVerifiedObject, settleCandidate, uploadCandidate, type CandidateDecision } from "./r2.js";
import {
  RECORD_KEY,
  recordCleanupFailure,
  type CapabilitySnapshot,
  type ObjectMetadata,
  type SendRecord
} from "./state.js";
import { decodeCanonicalBase64Url } from "./strict.js";

function objectKeys(record: SendRecord): readonly string[] {
  const keys = [...record.pendingKeys];
  if (record.object !== null) {
    keys.push(record.object.key);
  }
  return [...new Set(keys)];
}

function sameSnapshot(record: SendRecord, snapshot: CapabilitySnapshot, tag: string | null): boolean {
  return tag !== null && record.generation === snapshot.generation && record.authKeyId === snapshot.keyId && tag === snapshot.tag;
}

export async function commitFinalSendRelease(
  storage: DurableObjectStorage,
  snapshot: CapabilitySnapshot,
  object: ObjectMetadata,
  clock: () => number
): Promise<{ readonly expiresAt: number; readonly remaining: 0 } | null> {
  return storage.transaction(async (transaction) => {
    const nowMs = clock();
    const current = await transaction.get<SendRecord>(RECORD_KEY);
    if (
      current === undefined ||
      !sameSnapshot(current, snapshot, current.retrieveTag) ||
      current.state !== "active" ||
      current.serverExpiresAt <= unixSeconds(nowMs) ||
      current.object?.key !== object.key ||
      current.object.digest !== object.digest ||
      current.remainingRetrievals !== 1
    ) {
      return null;
    }
    const updated: SendRecord = {
      ...current,
      attemptId: null,
      clientNotAfter: null,
      generation: current.generation + 1,
      nextCleanupAt: nowMs,
      pendingKeys: [object.key],
      remainingRetrievals: 0,
      retrieveTag: null,
      state: "exhausted"
    };
    await transaction.put(RECORD_KEY, updated);
    await transaction.setAlarm(nowMs);
    return { expiresAt: updated.serverExpiresAt, remaining: 0 };
  });
}

export class SendDurableObject {
  readonly #context: DurableObjectState;
  readonly #rawEnvironment: WorkerEnv;
  readonly #bucket: R2Bucket;
  #checkedEnvironment: CheckedWorkerEnvironment | undefined;

  constructor(context: DurableObjectState, environment: WorkerEnv) {
    this.#context = context;
    this.#rawEnvironment = environment;
    this.#bucket = environment.CIPHERTEXT;
  }

  #environment(): CheckedWorkerEnvironment {
    this.#checkedEnvironment ??= checkWorkerEnvironment(this.#rawEnvironment);
    return this.#checkedEnvironment;
  }

  async fetch(request: Request): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    const text = await request.text();
    if (pathname === "/init") {
      return this.#initialize(text);
    }
    if (pathname === "/retrieve") {
      return this.#retrieve(text);
    }
    if (pathname === "/status") {
      return this.#status(text);
    }
    if (pathname === "/revoke") {
      return this.#revoke(text);
    }
    if (pathname === "/shorten") {
      return this.#shorten(text);
    }
    return unavailable();
  }

  async alarm(): Promise<void> {
    await this.#processCleanup(true);
  }

  async #initialize(text: string): Promise<Response> {
    const input = parseSendCreateRequestJson(text);
    const existing = await this.#context.storage.get<SendRecord>(RECORD_KEY);
    if (existing !== undefined) {
      if (existing.attemptId === input.attemptId) {
        return jsonResponse({ serverExpiresAt: existing.serverExpiresAt });
      }
      return unavailable();
    }
    if (unixSeconds() > input.settleNotAfter) {
      return unavailable();
    }

    const envelope = parseKxe1Envelope(input.envelope);
    const locator = decodeCanonicalBase64Url(input.locator, 16, "send locator");
    const retrieveToken = decodeCanonicalBase64Url(input.retrieveToken, 32, "retrieve token");
    const manageToken = decodeCanonicalBase64Url(input.manageToken, 32, "manage token");
    const [retrieveTag, manageTag] = await Promise.all([
      capabilityTag(this.#environment().activeCapabilityKey, 1, 1, locator, retrieveToken),
      capabilityTag(this.#environment().activeCapabilityKey, 1, 2, locator, manageToken)
    ]);
    const candidate = await uploadCandidate(this.#bucket, envelope.bytes);

    let decision: CandidateDecision<number>;
    try {
      decision = await settleCandidate(candidate, async () => {
        return this.#context.storage.transaction(async (transaction) => {
          const current = await transaction.get<SendRecord>(RECORD_KEY);
          if (current !== undefined) {
            if (current.attemptId === input.attemptId && current.object !== null) {
              return {
                kind: "committed",
                value: current.serverExpiresAt,
                winnerKey: current.object.key
              };
            }
            return { kind: "definitive_not_committed", value: 0 };
          }
          const now = unixSeconds();
          if (now > input.settleNotAfter) {
            return { kind: "definitive_not_committed", value: 0 };
          }
          const expiresAt = Math.min(input.clientNotAfter, now + input.ttlSeconds);
          const record: SendRecord = {
            attemptId: input.attemptId,
            authKeyId: this.#environment().activeCapabilityKeyId,
            cleanupFailureCount: 0,
            clientNotAfter: input.clientNotAfter,
            generation: 1,
            kind: "send",
            manageTag,
            maxRetrievals: input.maxRetrievals,
            nextCleanupAt: null,
            object: candidate,
            pendingKeys: [],
            remainingRetrievals: input.maxRetrievals,
            retrieveTag,
            serverExpiresAt: expiresAt,
            state: "active"
          };
          await transaction.put(RECORD_KEY, record);
          await transaction.setAlarm(expiresAt * 1_000);
          return { kind: "committed", value: expiresAt, winnerKey: candidate.key };
        });
      }, async (key) => deleteKeys(this.#bucket, [key]));
    } catch {
      throw new Error("ambiguous send initialization");
    }
    if (decision.kind === "definitive_not_committed") {
      return unavailable();
    }
    return jsonResponse({ serverExpiresAt: decision.value });
  }

  async #authenticate(locator: string, token: string, capabilityKind: 1 | 2) {
    const decoded = decodeAuthInput(locator, token);
    return authenticate(this.#context.storage, this.#environment(), {
      capabilityKind,
      locator: decoded.locator,
      resourceKind: 1,
      token: decoded.token
    });
  }

  async #retrieve(text: string): Promise<Response> {
    const input = parseSendRetrieveRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.retrieveToken, 1);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const snapshotRecord = await this.#context.storage.get<SendRecord>(RECORD_KEY);
    if (
      snapshotRecord === undefined ||
      !sameSnapshot(snapshotRecord, authentication.snapshot, snapshotRecord.retrieveTag) ||
      snapshotRecord.state !== "active" ||
      snapshotRecord.serverExpiresAt <= unixSeconds() ||
      snapshotRecord.object === null
    ) {
      await this.#markExpiredWhenNeeded();
      return unavailable();
    }
    const object = snapshotRecord.object;
    const bytes = await readVerifiedObject(this.#bucket, object);
    if (bytes === null) {
      return unavailable();
    }

    const release = snapshotRecord.remainingRetrievals === 1
      ? await commitFinalSendRelease(this.#context.storage, authentication.snapshot, object, Date.now)
      : this.#commitNonFinalRelease(authentication.snapshot, object);
    if (release === null) {
      return unavailable();
    }
    if (release.remaining === 0) {
      await this.#cleanupBestEffort();
    }
    return binaryResponse(bytes, {
      "Kryptex-Remaining-Releases": String(release.remaining),
      "Kryptex-Server-Expires-At": String(release.expiresAt)
    });
  }

  #commitNonFinalRelease(snapshot: CapabilitySnapshot, object: ObjectMetadata): { readonly expiresAt: number; readonly remaining: number } | null {
    return this.#context.storage.transactionSync(() => {
      const current = this.#context.storage.kv.get<SendRecord>(RECORD_KEY);
      if (
        current === undefined ||
        !sameSnapshot(current, snapshot, current.retrieveTag) ||
        current.state !== "active" ||
        current.serverExpiresAt <= unixSeconds() ||
        current.object?.key !== object.key ||
        current.object.digest !== object.digest ||
        current.remainingRetrievals <= 1
      ) {
        return null;
      }
      const remaining = current.remainingRetrievals - 1;
      const updated: SendRecord = { ...current, generation: current.generation + 1, remainingRetrievals: remaining };
      this.#context.storage.kv.put(RECORD_KEY, updated);
      return { expiresAt: updated.serverExpiresAt, remaining };
    });
  }

  async #status(text: string): Promise<Response> {
    const input = parseSendManageRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.manageToken, 2);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable({ "Kryptex-State-Checked-At": String(authentication.stateCheckedAt) });
    }
    const result = await this.#context.storage.transaction(async (transaction) => {
      const stateCheckedAt = unixSeconds();
      const current = await transaction.get<SendRecord>(RECORD_KEY);
      if (current === undefined || !sameSnapshot(current, authentication.snapshot, current.manageTag)) {
        return { record: undefined, stateCheckedAt };
      }
      if (current.serverExpiresAt <= stateCheckedAt && current.state !== "expired") {
        const expired: SendRecord = {
          ...current,
          attemptId: null,
          clientNotAfter: null,
          generation: current.generation + 1,
          nextCleanupAt: Date.now(),
          pendingKeys: objectKeys(current),
          retrieveTag: null,
          state: "expired"
        };
        await transaction.put(RECORD_KEY, expired);
        await transaction.setAlarm(Date.now());
        return { record: expired, stateCheckedAt };
      }
      return { record: current, stateCheckedAt };
    });
    const headers = { "Kryptex-State-Checked-At": String(result.stateCheckedAt) };
    if (result.record === undefined) {
      return unavailable(headers);
    }
    if (result.record.state === "expired") {
      this.#context.waitUntil(this.#cleanupBestEffort());
    }
    return jsonResponse(
      {
        remainingRetrievals: result.record.remainingRetrievals,
        serverExpiresAt: result.record.serverExpiresAt,
        state: result.record.state
      },
      200,
      headers
    );
  }

  async #revoke(text: string): Promise<Response> {
    const input = parseSendManageRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.manageToken, 2);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const changed = await this.#context.storage.transaction(async (transaction) => {
      const current = await transaction.get<SendRecord>(RECORD_KEY);
      if (
        current === undefined ||
        !sameSnapshot(current, authentication.snapshot, current.manageTag) ||
        current.state !== "active" ||
        current.serverExpiresAt <= unixSeconds()
      ) {
        return false;
      }
      const revoked: SendRecord = {
        ...current,
        attemptId: null,
        clientNotAfter: null,
        generation: current.generation + 1,
        nextCleanupAt: Date.now(),
        pendingKeys: objectKeys(current),
        retrieveTag: null,
        state: "revoked"
      };
      await transaction.put(RECORD_KEY, revoked);
      await transaction.setAlarm(Date.now());
      return true;
    });
    if (!changed) {
      await this.#markExpiredWhenNeeded();
      return unavailable();
    }
    await this.#cleanupBestEffort();
    return jsonResponse({ state: "revoked" });
  }

  async #shorten(text: string): Promise<Response> {
    const input = parseSendShortenRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.manageToken, 2);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const expiresAt = await this.#context.storage.transaction(async (transaction) => {
      const current = await transaction.get<SendRecord>(RECORD_KEY);
      const now = unixSeconds();
      if (
        current === undefined ||
        !sameSnapshot(current, authentication.snapshot, current.manageTag) ||
        (current.state !== "active" && current.state !== "exhausted") ||
        current.serverExpiresAt <= now ||
        input.serverExpiresAt <= now ||
        input.serverExpiresAt >= current.serverExpiresAt
      ) {
        return null;
      }
      const shortened: SendRecord = {
        ...current,
        generation: current.generation + 1,
        serverExpiresAt: input.serverExpiresAt
      };
      await transaction.put(RECORD_KEY, shortened);
      const cleanupAt = shortened.nextCleanupAt ?? shortened.serverExpiresAt * 1_000;
      await transaction.setAlarm(Math.min(shortened.serverExpiresAt * 1_000, cleanupAt));
      return shortened.serverExpiresAt;
    });
    return expiresAt === null ? unavailable() : jsonResponse({ serverExpiresAt: expiresAt });
  }

  async #markExpiredWhenNeeded(): Promise<void> {
    const changed = await this.#context.storage.transaction(async (transaction) => {
      const current = await transaction.get<SendRecord>(RECORD_KEY);
      if (current === undefined || current.serverExpiresAt > unixSeconds() || current.state === "expired") {
        return false;
      }
      const expired: SendRecord = {
        ...current,
        attemptId: null,
        clientNotAfter: null,
        generation: current.generation + 1,
        nextCleanupAt: Date.now(),
        pendingKeys: objectKeys(current),
        retrieveTag: null,
        state: "expired"
      };
      await transaction.put(RECORD_KEY, expired);
      await transaction.setAlarm(Date.now());
      return true;
    });
    if (changed) {
      this.#context.waitUntil(this.#cleanupBestEffort());
    }
  }

  async #cleanupBestEffort(): Promise<void> {
    try {
      await this.#processCleanup(false);
    } catch {
      return;
    }
  }

  async #processCleanup(throwOnFailure: boolean): Promise<void> {
    const nowMs = Date.now();
    const prepared = await this.#context.storage.transaction(async (transaction) => {
      const current = await transaction.get<SendRecord>(RECORD_KEY);
      if (current === undefined) {
        return undefined;
      }
      if (nowMs >= current.serverExpiresAt * 1_000 && current.state !== "expired") {
        const expired: SendRecord = {
          ...current,
          attemptId: null,
          clientNotAfter: null,
          generation: current.generation + 1,
          nextCleanupAt: nowMs,
          pendingKeys: objectKeys(current),
          retrieveTag: null,
          state: "expired"
        };
        await transaction.put(RECORD_KEY, expired);
        return expired;
      }
      return current;
    });
    if (prepared === undefined) {
      return;
    }
    const expired = nowMs >= prepared.serverExpiresAt * 1_000;
    const keys = expired ? objectKeys(prepared) : prepared.pendingKeys;
    if (keys.length === 0) {
      if (expired) {
        try {
          await this.#context.storage.deleteAll();
        } catch {
          await this.#scheduleCleanupFailure(keys, true, throwOnFailure);
        }
      } else {
        await this.#context.storage.setAlarm(prepared.serverExpiresAt * 1_000);
      }
      return;
    }
    const deleted = await deleteKeys(this.#bucket, keys);
    if (deleted && expired) {
      try {
        await this.#context.storage.deleteAll();
      } catch {
        await this.#scheduleCleanupFailure(keys, true, throwOnFailure);
      }
      return;
    }
    if (deleted) {
      await this.#context.storage.transaction(async (transaction) => {
        const current = await transaction.get<SendRecord>(RECORD_KEY);
        if (current === undefined) {
          return;
        }
        const cleared: SendRecord = {
          ...current,
          cleanupFailureCount: 0,
          generation: current.generation + 1,
          nextCleanupAt: null,
          object: current.state === "active" ? current.object : null,
          pendingKeys: []
        };
        await transaction.put(RECORD_KEY, cleared);
        await transaction.setAlarm(cleared.serverExpiresAt * 1_000);
      });
      return;
    }
    await this.#scheduleCleanupFailure(keys, expired, throwOnFailure);
  }

  async #scheduleCleanupFailure(keys: readonly string[], expired: boolean, throwOnFailure: boolean): Promise<void> {
    try {
      await recordCleanupFailure(this.#context.storage, keys, expired, Date.now);
    } catch (error) {
      if (throwOnFailure) {
        throw error;
      }
    }
  }
}
