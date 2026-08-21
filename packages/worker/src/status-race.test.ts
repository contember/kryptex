import { afterEach, describe, expect, test } from "vitest";
import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { finishAuthentication, reserveAuthentication } from "./auth.js";
import { RECORD_KEY, type RequestRecord, type SendRecord } from "./state.js";

afterEach(async () => {
  await reset();
});

function unavailableTimestamp(result: ReturnType<typeof finishAuthentication>): number {
  if (result.kind !== "unavailable") {
    throw new Error("expected unavailable authentication");
  }
  return result.stateCheckedAt;
}

describe("status settlement linearization", () => {
  test("a send init after a missing snapshot cannot inherit a later checked-at timestamp", async () => {
    const stub = env.SEND_OBJECTS.getByName("send-status-init-race");
    await runInDurableObject(stub, (_instance, state) => {
      const reservation = reserveAuthentication(
        state.storage,
        2,
        "dev-v1",
        "send-status-attempt",
        () => 1_800_000_000_000
      );
      if (reservation.kind !== "reserved") {
        throw new Error("reservation unexpectedly rate limited");
      }
      const settleNotAfter = reservation.reservation.stateCheckedAt + 1;
      const record: SendRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: settleNotAfter + 900,
        factorMode: 0,
        generation: 1,
        kind: "send",
        manageTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        maxRetrievals: 1,
        nextCleanupAt: null,
        object: null,
        pendingKeys: [],
        remainingRetrievals: 1,
        retrieveTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        serverExpiresAt: settleNotAfter + 900,
        state: "active"
      };
      state.storage.kv.put(RECORD_KEY, record);
      const result = finishAuthentication(
        state.storage,
        2,
        reservation.reservation,
        false,
        () => (settleNotAfter + 1) * 1_000
      );
      expect(unavailableTimestamp(result)).toBe(reservation.reservation.stateCheckedAt);
      expect(unavailableTimestamp(result)).toBeLessThanOrEqual(settleNotAfter);
    });
  });

  test("a request init after a missing snapshot cannot inherit a later checked-at timestamp", async () => {
    const stub = env.REQUEST_OBJECTS.getByName("request-status-init-race");
    await runInDurableObject(stub, (_instance, state) => {
      const reservation = reserveAuthentication(
        state.storage,
        2,
        "dev-v1",
        "request-status-attempt",
        () => 1_800_000_000_000
      );
      if (reservation.kind !== "reserved") {
        throw new Error("reservation unexpectedly rate limited");
      }
      const settleNotAfter = reservation.reservation.stateCheckedAt + 1;
      const record: RequestRecord = {
        attemptId: "AAAAAAAAAAAAAAAAAAAAAA",
        authKeyId: "dev-v1",
        cleanupFailureCount: 0,
        clientNotAfter: settleNotAfter + 900,
        factorMode: 0,
        generation: 1,
        kind: "request",
        nextCleanupAt: null,
        ownerTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        pendingKeys: [],
        responseAttemptId: null,
        responseObject: null,
        schemaDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        schemaObject: null,
        serverExpiresAt: settleNotAfter + 900,
        state: "waiting",
        writeTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      };
      state.storage.kv.put(RECORD_KEY, record);
      const result = finishAuthentication(
        state.storage,
        2,
        reservation.reservation,
        false,
        () => (settleNotAfter + 1) * 1_000
      );
      expect(unavailableTimestamp(result)).toBe(reservation.reservation.stateCheckedAt);
      expect(unavailableTimestamp(result)).toBeLessThanOrEqual(settleNotAfter);
    });
  });
});
