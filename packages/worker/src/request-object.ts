import {
  parseRequestCreateRequestJson,
  parseRequestOwnerRequestJson,
  parseRequestShortenRequestJson,
  parseRequestSubmitRequestJson,
  parseRequestWriteRequestJson
} from "@kryptex/contracts/api";
import { parseKxe1Envelope, parseKxr1Envelope } from "@kryptex/contracts/envelopes";
import { authenticate, decodeAuthInput } from "./auth.js";
import { capabilityTag, encodeBase64Url, unixSeconds } from "./core.js";
import { checkWorkerEnvironment, type CheckedWorkerEnvironment, type WorkerEnv } from "./env.js";
import { binaryResponse, jsonResponse, rateLimited, unavailable } from "./http.js";
import { deleteKeys, readVerifiedObject, settleCandidate, uploadCandidate, type CandidateDecision } from "./r2.js";
import {
  RECORD_KEY,
  recordCleanupFailure,
  type CapabilitySnapshot,
  type ObjectMetadata,
  type RequestRecord
} from "./state.js";
import { decodeCanonicalBase64Url, exactObject, parseJson, stringProperty } from "./strict.js";

interface SubmitInput {
  readonly attemptId: string;
  readonly envelope: string;
  readonly locator: string;
  readonly writeToken: string;
}

function parseSubmitInput(text: string): SubmitInput {
  const object = exactObject(parseJson(text), ["attemptId", "envelope", "locator", "writeToken"], "request submit");
  const attemptId = stringProperty(object, "attemptId", "request submit");
  const envelope = stringProperty(object, "envelope", "request submit");
  const locator = stringProperty(object, "locator", "request submit");
  const writeToken = stringProperty(object, "writeToken", "request submit");
  decodeCanonicalBase64Url(attemptId, 16, "submit attempt ID");
  parseRequestSubmitRequestJson(JSON.stringify({ envelope, locator, writeToken }));
  return { attemptId, envelope, locator, writeToken };
}

function objectKeys(record: RequestRecord): readonly string[] {
  const keys = [...record.pendingKeys];
  if (record.schemaObject !== null) {
    keys.push(record.schemaObject.key);
  }
  if (record.responseObject !== null) {
    keys.push(record.responseObject.key);
  }
  return [...new Set(keys)];
}

function sameSnapshot(record: RequestRecord, snapshot: CapabilitySnapshot, tag: string | null): boolean {
  return tag !== null && record.generation === snapshot.generation && record.authKeyId === snapshot.keyId && tag === snapshot.tag;
}

export async function commitRequestSubmission(
  storage: DurableObjectStorage,
  snapshot: CapabilitySnapshot,
  attemptId: string,
  candidate: ObjectMetadata,
  clock: () => number
): Promise<CandidateDecision<string>> {
  return storage.transaction(async (transaction) => {
    const now = unixSeconds(clock());
    const stored = await transaction.get<RequestRecord>(RECORD_KEY);
    if (
      stored?.state === "submitted" &&
      stored.responseAttemptId === attemptId &&
      stored.responseObject !== null
    ) {
      return {
        kind: "committed",
        value: stored.responseObject.digest,
        winnerKey: stored.responseObject.key
      };
    }
    if (
      stored === undefined ||
      !sameSnapshot(stored, snapshot, stored.writeTag) ||
      stored.state !== "waiting" ||
      stored.serverExpiresAt <= now
    ) {
      return { kind: "definitive_not_committed", value: "" };
    }
    const submitted: RequestRecord = {
      ...stored,
      generation: stored.generation + 1,
      responseAttemptId: attemptId,
      responseObject: candidate,
      state: "submitted"
    };
    await transaction.put(RECORD_KEY, submitted);
    return { kind: "committed", value: candidate.digest, winnerKey: candidate.key };
  });
}

export async function commitRequestPickup(
  storage: DurableObjectStorage,
  snapshot: CapabilitySnapshot,
  object: ObjectMetadata,
  clock: () => number
): Promise<{ readonly expiresAt: number; readonly receipt: string } | null> {
  return storage.transaction(async (transaction) => {
    const nowMs = clock();
    const current = await transaction.get<RequestRecord>(RECORD_KEY);
    if (
      current === undefined ||
      !sameSnapshot(current, snapshot, current.ownerTag) ||
      current.state !== "submitted" ||
      current.serverExpiresAt <= unixSeconds(nowMs) ||
      current.responseObject?.key !== object.key ||
      current.responseObject.digest !== object.digest
    ) {
      return null;
    }
    const pickedUp: RequestRecord = {
      ...current,
      attemptId: null,
      clientNotAfter: null,
      generation: current.generation + 1,
      nextCleanupAt: nowMs,
      pendingKeys: objectKeys(current),
      responseAttemptId: null,
      schemaDigest: null,
      state: "picked_up",
      writeTag: null
    };
    await transaction.put(RECORD_KEY, pickedUp);
    await transaction.setAlarm(nowMs);
    return { expiresAt: pickedUp.serverExpiresAt, receipt: object.digest };
  });
}

export class RequestDurableObject {
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
    if (pathname === "/schema") {
      return this.#schema(text);
    }
    if (pathname === "/submit") {
      return this.#submit(text);
    }
    if (pathname === "/status") {
      return this.#status(text);
    }
    if (pathname === "/pickup") {
      return this.#pickup(text);
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
    const input = parseRequestCreateRequestJson(text);
    const existing = await this.#context.storage.get<RequestRecord>(RECORD_KEY);
    if (existing !== undefined) {
      return existing.attemptId === input.attemptId
        ? jsonResponse({ serverExpiresAt: existing.serverExpiresAt })
        : unavailable();
    }
    if (unixSeconds() > input.settleNotAfter) {
      return unavailable();
    }
    const envelope = parseKxe1Envelope(input.envelope);
    const locator = decodeCanonicalBase64Url(input.locator, 16, "request locator");
    const writeToken = decodeCanonicalBase64Url(input.writeToken, 32, "write token");
    const ownerToken = decodeCanonicalBase64Url(input.ownerToken, 32, "owner token");
    const [writeTag, ownerTag] = await Promise.all([
      capabilityTag(this.#environment().activeCapabilityKey, 2, 1, locator, writeToken),
      capabilityTag(this.#environment().activeCapabilityKey, 2, 2, locator, ownerToken)
    ]);
    const candidate = await uploadCandidate(this.#bucket, envelope.bytes);
    const schemaDigest = encodeBase64Url(envelope.schemaDigest);
    let decision: CandidateDecision<number>;
    try {
      decision = await settleCandidate(candidate, async () => {
        return this.#context.storage.transaction(async (transaction) => {
          const current = await transaction.get<RequestRecord>(RECORD_KEY);
          if (current !== undefined) {
            return current.attemptId === input.attemptId && current.schemaObject !== null
              ? { kind: "committed", value: current.serverExpiresAt, winnerKey: current.schemaObject.key }
              : { kind: "definitive_not_committed", value: 0 };
          }
          const now = unixSeconds();
          if (now > input.settleNotAfter) {
            return { kind: "definitive_not_committed", value: 0 };
          }
          const expiresAt = Math.min(input.clientNotAfter, now + input.ttlSeconds);
          const record: RequestRecord = {
            attemptId: input.attemptId,
            authKeyId: this.#environment().activeCapabilityKeyId,
            cleanupFailureCount: 0,
            clientNotAfter: input.clientNotAfter,
            factorMode: envelope.factorMode,
            generation: 1,
            kind: "request",
            nextCleanupAt: null,
            ownerTag,
            pendingKeys: [],
            responseAttemptId: null,
            responseObject: null,
            schemaDigest,
            schemaObject: candidate,
            serverExpiresAt: expiresAt,
            state: "waiting",
            writeTag
          };
          await transaction.put(RECORD_KEY, record);
          await transaction.setAlarm(expiresAt * 1_000);
          return { kind: "committed", value: expiresAt, winnerKey: candidate.key };
        });
      }, async (key) => deleteKeys(this.#bucket, [key]));
    } catch {
      throw new Error("ambiguous request initialization");
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
      resourceKind: 2,
      token: decoded.token
    });
  }

  async #schema(text: string): Promise<Response> {
    const input = parseRequestWriteRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.writeToken, 1);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const snapshotRecord = await this.#context.storage.get<RequestRecord>(RECORD_KEY);
    if (
      snapshotRecord === undefined ||
      !sameSnapshot(snapshotRecord, authentication.snapshot, snapshotRecord.writeTag) ||
      snapshotRecord.state !== "waiting" ||
      snapshotRecord.serverExpiresAt <= unixSeconds() ||
      snapshotRecord.schemaObject === null
    ) {
      await this.#markExpiredWhenNeeded();
      return unavailable();
    }
    const object = snapshotRecord.schemaObject;
    const bytes = await readVerifiedObject(this.#bucket, object);
    if (bytes === null) {
      return unavailable();
    }
    const valid = this.#context.storage.transactionSync(() => {
      const current = this.#context.storage.kv.get<RequestRecord>(RECORD_KEY);
      return current !== undefined &&
        sameSnapshot(current, authentication.snapshot, current.writeTag) &&
        current.state === "waiting" &&
        current.serverExpiresAt > unixSeconds() &&
        current.schemaObject?.key === object.key &&
        current.schemaObject.digest === object.digest;
    });
    return valid
      ? binaryResponse(bytes, { "Kryptex-Server-Expires-At": String(snapshotRecord.serverExpiresAt) })
      : unavailable();
  }

  async #submit(text: string): Promise<Response> {
    const input = parseSubmitInput(text);
    const authentication = await this.#authenticate(input.locator, input.writeToken, 1);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const envelope = parseKxr1Envelope(input.envelope);
    const current = await this.#context.storage.get<RequestRecord>(RECORD_KEY);
    if (
      current?.state === "submitted" &&
      current.responseAttemptId === input.attemptId &&
      current.responseObject !== null
    ) {
      return jsonResponse({ receipt: current.responseObject.digest });
    }
    if (
      current === undefined ||
      !sameSnapshot(current, authentication.snapshot, current.writeTag) ||
      current.state !== "waiting" ||
      current.serverExpiresAt <= unixSeconds() ||
      current.clientNotAfter === null ||
      current.schemaDigest === null ||
      envelope.clientNotAfter !== current.clientNotAfter ||
      encodeBase64Url(envelope.schemaDigest) !== current.schemaDigest
    ) {
      await this.#markExpiredWhenNeeded();
      return unavailable();
    }
    const candidate = await uploadCandidate(this.#bucket, envelope.bytes);
    let decision: CandidateDecision<string>;
    try {
      decision = await settleCandidate(candidate, async () => {
        return commitRequestSubmission(
          this.#context.storage,
          authentication.snapshot,
          input.attemptId,
          candidate,
          Date.now
        );
      }, async (key) => deleteKeys(this.#bucket, [key]));
    } catch {
      throw new Error("ambiguous request submission");
    }
    if (decision.kind === "definitive_not_committed") {
      return unavailable();
    }
    return jsonResponse({ receipt: decision.value });
  }

  async #status(text: string): Promise<Response> {
    const input = parseRequestOwnerRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.ownerToken, 2);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable({ "Kryptex-State-Checked-At": String(authentication.stateCheckedAt) });
    }
    const result = await this.#context.storage.transaction(async (transaction) => {
      const stateCheckedAt = unixSeconds();
      const current = await transaction.get<RequestRecord>(RECORD_KEY);
      if (current === undefined || !sameSnapshot(current, authentication.snapshot, current.ownerTag)) {
        return { record: undefined, stateCheckedAt };
      }
      if (current.serverExpiresAt <= stateCheckedAt && current.state !== "expired") {
        const expired: RequestRecord = {
          ...current,
          attemptId: null,
          clientNotAfter: null,
          generation: current.generation + 1,
          nextCleanupAt: Date.now(),
          pendingKeys: objectKeys(current),
          responseAttemptId: null,
          schemaDigest: null,
          state: "expired",
          writeTag: null
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
    return jsonResponse({ serverExpiresAt: result.record.serverExpiresAt, state: result.record.state }, 200, headers);
  }

  async #pickup(text: string): Promise<Response> {
    const input = parseRequestOwnerRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.ownerToken, 2);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const snapshotRecord = await this.#context.storage.get<RequestRecord>(RECORD_KEY);
    if (
      snapshotRecord === undefined ||
      !sameSnapshot(snapshotRecord, authentication.snapshot, snapshotRecord.ownerTag) ||
      snapshotRecord.state !== "submitted" ||
      snapshotRecord.serverExpiresAt <= unixSeconds() ||
      snapshotRecord.responseObject === null
    ) {
      await this.#markExpiredWhenNeeded();
      return unavailable();
    }
    const object = snapshotRecord.responseObject;
    const bytes = await readVerifiedObject(this.#bucket, object);
    if (bytes === null) {
      return unavailable();
    }
    const release = await commitRequestPickup(this.#context.storage, authentication.snapshot, object, Date.now);
    if (release === null) {
      return unavailable();
    }
    await this.#cleanupBestEffort();
    return binaryResponse(bytes, {
      "Kryptex-Receipt": release.receipt,
      "Kryptex-Server-Expires-At": String(release.expiresAt)
    });
  }

  async #revoke(text: string): Promise<Response> {
    const input = parseRequestOwnerRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.ownerToken, 2);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const changed = await this.#context.storage.transaction(async (transaction) => {
      const current = await transaction.get<RequestRecord>(RECORD_KEY);
      if (
        current === undefined ||
        !sameSnapshot(current, authentication.snapshot, current.ownerTag) ||
        (current.state !== "waiting" && current.state !== "submitted") ||
        current.serverExpiresAt <= unixSeconds()
      ) {
        return false;
      }
      const revoked: RequestRecord = {
        ...current,
        attemptId: null,
        clientNotAfter: null,
        generation: current.generation + 1,
        nextCleanupAt: Date.now(),
        pendingKeys: objectKeys(current),
        responseAttemptId: null,
        schemaDigest: null,
        state: "revoked",
        writeTag: null
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
    const input = parseRequestShortenRequestJson(text);
    const authentication = await this.#authenticate(input.locator, input.ownerToken, 2);
    if (authentication.kind === "rate_limited") {
      return rateLimited();
    }
    if (authentication.kind === "unavailable") {
      return unavailable();
    }
    const expiresAt = await this.#context.storage.transaction(async (transaction) => {
      const current = await transaction.get<RequestRecord>(RECORD_KEY);
      const now = unixSeconds();
      if (
        current === undefined ||
        !sameSnapshot(current, authentication.snapshot, current.ownerTag) ||
        (current.state !== "waiting" && current.state !== "submitted") ||
        current.serverExpiresAt <= now ||
        input.serverExpiresAt <= now ||
        input.serverExpiresAt >= current.serverExpiresAt
      ) {
        return null;
      }
      const shortened: RequestRecord = {
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
      const current = await transaction.get<RequestRecord>(RECORD_KEY);
      if (current === undefined || current.serverExpiresAt > unixSeconds() || current.state === "expired") {
        return false;
      }
      const expired: RequestRecord = {
        ...current,
        attemptId: null,
        clientNotAfter: null,
        generation: current.generation + 1,
        nextCleanupAt: Date.now(),
        pendingKeys: objectKeys(current),
        responseAttemptId: null,
        schemaDigest: null,
        state: "expired",
        writeTag: null
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
      const current = await transaction.get<RequestRecord>(RECORD_KEY);
      if (current === undefined) {
        return undefined;
      }
      if (nowMs >= current.serverExpiresAt * 1_000 && current.state !== "expired") {
        const expired: RequestRecord = {
          ...current,
          attemptId: null,
          clientNotAfter: null,
          generation: current.generation + 1,
          nextCleanupAt: nowMs,
          pendingKeys: objectKeys(current),
          responseAttemptId: null,
          schemaDigest: null,
          state: "expired",
          writeTag: null
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
        const current = await transaction.get<RequestRecord>(RECORD_KEY);
        if (current === undefined) {
          return;
        }
        const terminal = current.state === "picked_up" || current.state === "revoked" || current.state === "expired";
        const cleared: RequestRecord = {
          ...current,
          cleanupFailureCount: 0,
          generation: current.generation + 1,
          nextCleanupAt: null,
          pendingKeys: [],
          responseObject: terminal ? null : current.responseObject,
          schemaObject: terminal ? null : current.schemaObject
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
