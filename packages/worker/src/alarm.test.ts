import { afterEach, describe, expect, test } from "vitest";
import { env } from "cloudflare:workers";
import { reset, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { RECORD_KEY, recordCleanupFailure, type RequestRecord, type SendRecord } from "./state.js";

afterEach(async () => {
  await reset();
});

describe("terminal expiry alarms", () => {
  test("retains every pickup object and exponentially replaces the cleanup alarm after R2 failures", async () => {
    const stub = env.REQUEST_OBJECTS.getByName("alarm-delete-failure-request");
    const nowMs = 1_800_000_000_000;
    const record: RequestRecord = {
      attemptId: null,
      authKeyId: "dev-v1",
      cleanupFailureCount: 0,
      clientNotAfter: null,
      generation: 3,
      kind: "request",
      nextCleanupAt: nowMs,
      ownerTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      pendingKeys: [],
      responseAttemptId: null,
      responseObject: { digest: "response-digest", key: "response", length: 128 },
      schemaDigest: null,
      schemaObject: { digest: "schema-digest", key: "schema", length: 128 },
      serverExpiresAt: Math.floor(nowMs / 1_000),
      state: "picked_up",
      writeTag: null
    };
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put(RECORD_KEY, record);
      await recordCleanupFailure(state.storage, ["schema", "response"], true, () => nowMs);
      let stored = await state.storage.get<RequestRecord>(RECORD_KEY);
      expect(stored?.pendingKeys).toEqual(["schema", "response"]);
      expect(stored?.responseObject?.key).toBe("response");
      expect(stored?.schemaObject?.key).toBe("schema");
      expect(stored?.cleanupFailureCount).toBe(1);
      expect(stored?.nextCleanupAt).toBe(nowMs + 2_000);
      expect(await state.storage.getAlarm()).toBe(nowMs + 2_000);

      await recordCleanupFailure(state.storage, ["schema", "response"], true, () => nowMs);
      stored = await state.storage.get<RequestRecord>(RECORD_KEY);
      expect(stored?.pendingKeys).toEqual(["schema", "response"]);
      expect(stored?.cleanupFailureCount).toBe(2);
      expect(stored?.nextCleanupAt).toBe(nowMs + 4_000);
      expect(await state.storage.getAlarm()).toBe(nowMs + 4_000);
    });
  });

  test("expires an active send when its alarm runs after the deadline", async () => {
    const stub = env.SEND_OBJECTS.getByName("alarm-active-send");
    const record: SendRecord = {
      attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
      authKeyId: "dev-v1",
      cleanupFailureCount: 0,
      clientNotAfter: 1,
      generation: 1,
      kind: "send",
      manageTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      maxRetrievals: 1,
      nextCleanupAt: null,
      object: null,
      pendingKeys: [],
      remainingRetrievals: 1,
      retrieveTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      serverExpiresAt: 1,
      state: "active"
    };
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put(RECORD_KEY, record);
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get(RECORD_KEY)).toBeUndefined();
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  test("cleans pending keys before expiry and retains the expiry alarm", async () => {
    const stub = env.REQUEST_OBJECTS.getByName("alarm-pending-request");
    const serverExpiresAt = Math.floor(Date.now() / 1_000) + 3_600;
    const record: RequestRecord = {
      attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
      authKeyId: "dev-v1",
      cleanupFailureCount: 1,
      clientNotAfter: serverExpiresAt,
      generation: 1,
      kind: "request",
      nextCleanupAt: Date.now(),
      ownerTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      pendingKeys: ["v1/candidates/already-absent"],
      responseAttemptId: null,
      responseObject: null,
      schemaDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      schemaObject: null,
      serverExpiresAt,
      state: "waiting",
      writeTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    };
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put(RECORD_KEY, record);
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      const stored = await state.storage.get<RequestRecord>(RECORD_KEY);
      expect(stored?.state).toBe("waiting");
      expect(stored?.pendingKeys).toEqual([]);
      expect(stored?.cleanupFailureCount).toBe(0);
      expect(await state.storage.getAlarm()).toBe(serverExpiresAt * 1_000);
    });
  });

  test("deletes an expired send tombstone and its alarm", async () => {
    const stub = env.SEND_OBJECTS.getByName("alarm-send");
    const record: SendRecord = {
      attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
      authKeyId: "dev-v1",
      cleanupFailureCount: 0,
      clientNotAfter: 1,
      generation: 1,
      kind: "send",
      manageTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      maxRetrievals: 1,
      nextCleanupAt: Date.now() - 1,
      object: null,
      pendingKeys: [],
      remainingRetrievals: 0,
      retrieveTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      serverExpiresAt: 1,
      state: "expired"
    };
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put(RECORD_KEY, record);
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get(RECORD_KEY)).toBeUndefined();
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  test("deletes an expired request tombstone and its alarm", async () => {
    const stub = env.REQUEST_OBJECTS.getByName("alarm-request");
    const record: RequestRecord = {
      attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
      authKeyId: "dev-v1",
      cleanupFailureCount: 0,
      clientNotAfter: 1,
      generation: 1,
      kind: "request",
      nextCleanupAt: Date.now() - 1,
      ownerTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      pendingKeys: [],
      responseAttemptId: null,
      responseObject: null,
      schemaDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      schemaObject: null,
      serverExpiresAt: 1,
      state: "expired",
      writeTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    };
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put(RECORD_KEY, record);
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get(RECORD_KEY)).toBeUndefined();
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });
});
