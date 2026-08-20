import { afterEach, describe, expect, test } from "vitest";
import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { commitPermitOperation } from "./permit-object.js";
import { commitRequestPickup, commitRequestSubmission } from "./request-object.js";
import { commitFinalSendRelease } from "./send-object.js";
import {
  RECORD_KEY,
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
  test("commits exactly one final send release after two callers already authorized", async () => {
    const stub = env.SEND_OBJECTS.getByName("cas-final-send");
    await runInDurableObject(stub, async (_instance, state) => {
      const object = metadata("send-object", "send-digest");
      const record: SendRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: EXPIRES_AT,
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
