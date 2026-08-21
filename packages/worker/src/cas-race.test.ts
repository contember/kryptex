import { afterEach, describe, expect, test } from "vitest";
import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { commitPermitOperation } from "./permit-object.js";
import { finishAuthentication, reserveAuthentication } from "./auth.js";
import { commitRequestPickup, commitRequestSubmission } from "./request-object.js";
import { commitFinalSendRelease } from "./send-object.js";
import {
  AUTH_FAILURE_SATURATION,
  RECORD_KEY,
  authDelayMs,
  authKey,
  type AuthLease,
  type CapabilitySnapshot,
  type ObjectMetadata,
  type PermitRecord,
  type RequestRecord,
  type SendRecord
} from "./state.js";

const NOW_MS = 1_800_000_000_000;
const EXPIRES_AT = Math.floor(NOW_MS / 1_000) + 900;
const TAG = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

afterEach(async () => {
  await reset();
});

function metadata(key: string, digest: string): ObjectMetadata {
  return { digest, key, length: 128 };
}

function snapshot(generation: number): CapabilitySnapshot {
  return { generation, keyId: "dev-v1", tag: TAG };
}

describe("authorized final CAS transitions", () => {
  test("keeps authentication backoff isolated by capability kind", async () => {
    const stub = env.SEND_OBJECTS.getByName("auth-kind-isolation");
    await runInDurableObject(stub, async (_instance, state) => {
      const record: SendRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: EXPIRES_AT,
        factorMode: 0,
        generation: 1,
        kind: "send",
        manageTag: TAG,
        maxRetrievals: 1,
        nextCleanupAt: null,
        object: metadata("send-object", "send-digest"),
        pendingKeys: [],
        remainingRetrievals: 1,
        retrieveTag: TAG,
        serverExpiresAt: EXPIRES_AT,
        state: "active"
      };
      await state.storage.put(RECORD_KEY, record);

      const retrieve = reserveAuthentication(state.storage, 1, "dev-v1", "retrieve-attempt", () => NOW_MS);
      expect(retrieve.kind).toBe("reserved");
      if (retrieve.kind !== "reserved") throw new Error("Retrieve authentication was not reserved");
      expect(finishAuthentication(state.storage, 1, retrieve.reservation, false, () => NOW_MS).kind).toBe("unavailable");

      const manage = reserveAuthentication(state.storage, 2, "dev-v1", "manage-attempt", () => NOW_MS);
      expect(manage.kind).toBe("reserved");
      if (manage.kind !== "reserved") throw new Error("Manage authentication was not reserved");
      expect(finishAuthentication(state.storage, 2, manage.reservation, true, () => NOW_MS).kind).toBe("authorized");

      expect(reserveAuthentication(state.storage, 1, "dev-v1", "retrieve-retry", () => NOW_MS + 1).kind).toBe("rate_limited");
    });
  });

  test("caps the backoff curve at 30 seconds, or one hour where a passphrase can be guessed", () => {
    expect(authDelayMs(1, false)).toBe(250);
    expect(authDelayMs(1, true)).toBe(250);
    expect(authDelayMs(8, false)).toBe(30_000);
    expect(authDelayMs(8, true)).toBe(32_000);
    expect(authDelayMs(AUTH_FAILURE_SATURATION, false)).toBe(30_000);
    expect(authDelayMs(AUTH_FAILURE_SATURATION, true)).toBe(3_600_000);
  });

  test("applies the hour-long cap only to the passphrase-derived capability", async () => {
    const stub = env.SEND_OBJECTS.getByName("auth-passphrase-backoff");
    await runInDurableObject(stub, async (_instance, state) => {
      const record: SendRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: EXPIRES_AT,
        factorMode: 1,
        generation: 1,
        kind: "send",
        manageTag: TAG,
        maxRetrievals: 1,
        nextCleanupAt: null,
        object: metadata("send-object", "send-digest"),
        pendingKeys: [],
        remainingRetrievals: 1,
        retrieveTag: TAG,
        serverExpiresAt: EXPIRES_AT,
        state: "active"
      };
      await state.storage.put(RECORD_KEY, record);
      const saturated: AuthLease = { attemptId: "", authBusyUntil: 0, failureCount: AUTH_FAILURE_SATURATION, nextAuthAt: 0 };
      await state.storage.put(authKey(1), saturated);
      await state.storage.put(authKey(2), saturated);

      const retrieve = reserveAuthentication(state.storage, 1, "dev-v1", "retrieve-attempt", () => NOW_MS);
      if (retrieve.kind !== "reserved") throw new Error("Retrieve authentication was not reserved");
      expect(finishAuthentication(state.storage, 1, retrieve.reservation, false, () => NOW_MS).kind).toBe("unavailable");
      expect((await state.storage.get<AuthLease>(authKey(1)))?.nextAuthAt).toBe(NOW_MS + 3_600_000);

      const manage = reserveAuthentication(state.storage, 2, "dev-v1", "manage-attempt", () => NOW_MS);
      if (manage.kind !== "reserved") throw new Error("Manage authentication was not reserved");
      expect(finishAuthentication(state.storage, 2, manage.reservation, false, () => NOW_MS).kind).toBe("unavailable");
      expect((await state.storage.get<AuthLease>(authKey(2)))?.nextAuthAt).toBe(NOW_MS + 30_000);
    });
  });

  test("keeps the short cap for a retrieve token that carries a random second key", async () => {
    const stub = env.SEND_OBJECTS.getByName("auth-random-factor-backoff");
    await runInDurableObject(stub, async (_instance, state) => {
      const record: SendRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: EXPIRES_AT,
        factorMode: 2,
        generation: 1,
        kind: "send",
        manageTag: TAG,
        maxRetrievals: 1,
        nextCleanupAt: null,
        object: metadata("send-object", "send-digest"),
        pendingKeys: [],
        remainingRetrievals: 1,
        retrieveTag: TAG,
        serverExpiresAt: EXPIRES_AT,
        state: "active"
      };
      await state.storage.put(RECORD_KEY, record);
      await state.storage.put<AuthLease>(authKey(1), { attemptId: "", authBusyUntil: 0, failureCount: AUTH_FAILURE_SATURATION, nextAuthAt: 0 });

      const retrieve = reserveAuthentication(state.storage, 1, "dev-v1", "retrieve-attempt", () => NOW_MS);
      if (retrieve.kind !== "reserved") throw new Error("Retrieve authentication was not reserved");
      expect(finishAuthentication(state.storage, 1, retrieve.reservation, false, () => NOW_MS).kind).toBe("unavailable");
      expect((await state.storage.get<AuthLease>(authKey(1)))?.nextAuthAt).toBe(NOW_MS + 30_000);
    });
  });

  test("commits exactly one final send release after two callers already authorized", async () => {
    const stub = env.SEND_OBJECTS.getByName("cas-final-send");
    await runInDurableObject(stub, async (_instance, state) => {
      const object = metadata("send-object", "send-digest");
      const record: SendRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: EXPIRES_AT,
        factorMode: 0,
        generation: 1,
        kind: "send",
        manageTag: TAG,
        maxRetrievals: 1,
        nextCleanupAt: null,
        object,
        pendingKeys: [],
        remainingRetrievals: 1,
        retrieveTag: TAG,
        serverExpiresAt: EXPIRES_AT,
        state: "active"
      };
      await state.storage.put(RECORD_KEY, record);
      const results = await Promise.all([
        commitFinalSendRelease(state.storage, snapshot(1), object, () => NOW_MS),
        commitFinalSendRelease(state.storage, snapshot(1), object, () => NOW_MS)
      ]);
      expect(results.filter((result) => result !== null)).toHaveLength(1);
      const stored = await state.storage.get<SendRecord>(RECORD_KEY);
      expect(stored?.state).toBe("exhausted");
      expect(stored?.remainingRetrievals).toBe(0);
      expect(await state.storage.getAlarm()).toBe(NOW_MS);
    });
  });

  test("commits exactly one request submission after two writers already authorized", async () => {
    const stub = env.REQUEST_OBJECTS.getByName("cas-submit-request");
    await runInDurableObject(stub, async (_instance, state) => {
      const schemaObject = metadata("schema", "schema-digest");
      const record: RequestRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: EXPIRES_AT,
        factorMode: 0,
        generation: 1,
        kind: "request",
        nextCleanupAt: null,
        ownerTag: TAG,
        pendingKeys: [],
        responseAttemptId: null,
        responseObject: null,
        schemaDigest: "schema-digest",
        schemaObject,
        serverExpiresAt: EXPIRES_AT,
        state: "waiting",
        writeTag: TAG
      };
      await state.storage.put(RECORD_KEY, record);
      const first = metadata("response-first", "response-digest-first");
      const second = metadata("response-second", "response-digest-second");
      const results = await Promise.all([
        commitRequestSubmission(state.storage, snapshot(1), "attempt-first", first, () => NOW_MS),
        commitRequestSubmission(state.storage, snapshot(1), "attempt-second", second, () => NOW_MS)
      ]);
      expect(results.filter((result) => result.kind === "committed")).toHaveLength(1);
      expect(results.filter((result) => result.kind === "definitive_not_committed")).toHaveLength(1);
      const stored = await state.storage.get<RequestRecord>(RECORD_KEY);
      expect(stored?.state).toBe("submitted");
      expect([first.key, second.key]).toContain(stored?.responseObject?.key);
    });
  });

  test("commits exactly one pickup after two owners already authorized", async () => {
    const stub = env.REQUEST_OBJECTS.getByName("cas-pickup-request");
    await runInDurableObject(stub, async (_instance, state) => {
      const schemaObject = metadata("schema", "schema-digest");
      const responseObject = metadata("response", "response-digest");
      const record: RequestRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: EXPIRES_AT,
        factorMode: 0,
        generation: 2,
        kind: "request",
        nextCleanupAt: null,
        ownerTag: TAG,
        pendingKeys: [],
        responseAttemptId: "response-attempt",
        responseObject,
        schemaDigest: "schema-digest",
        schemaObject,
        serverExpiresAt: EXPIRES_AT,
        state: "submitted",
        writeTag: TAG
      };
      await state.storage.put(RECORD_KEY, record);
      const results = await Promise.all([
        commitRequestPickup(state.storage, snapshot(2), responseObject, () => NOW_MS),
        commitRequestPickup(state.storage, snapshot(2), responseObject, () => NOW_MS)
      ]);
      expect(results.filter((result) => result !== null)).toHaveLength(1);
      const stored = await state.storage.get<RequestRecord>(RECORD_KEY);
      expect(stored?.state).toBe("picked_up");
      expect(stored?.pendingKeys).toEqual(["schema", "response"]);
      expect(await state.storage.getAlarm()).toBe(NOW_MS);
    });
  });

  test("consumes a permit once after two callers already authorized", async () => {
    const stub = env.CREATE_PERMIT_OBJECTS.getByName("cas-permit");
    await runInDurableObject(stub, async (_instance, state) => {
      const record: PermitRecord = {
        authKeyId: "dev-v1",
        createdAt: Math.floor(NOW_MS / 1_000),
        generation: 1,
        kind: "permit",
        permitExpiresAt: EXPIRES_AT,
        state: "unused",
        tag: TAG
      };
      await state.storage.put(RECORD_KEY, record);
      const results = [
        commitPermitOperation(state.storage, snapshot(1), true, () => NOW_MS),
        commitPermitOperation(state.storage, snapshot(1), true, () => NOW_MS)
      ];
      expect(results.filter((result) => result !== undefined)).toHaveLength(1);
      expect((await state.storage.get<PermitRecord>(RECORD_KEY))?.state).toBe("consumed");
    });
  });
});
