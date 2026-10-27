import { describe, expect, it } from "vitest";
import type { RequestStatusResponse, SendStatusResponse, StateCheckedMetadata } from "@kryptex/contracts/api";
import { ApiFailure } from "./api-client.js";
import { pickupRecoveryForStatus, reconcileRequestCreation, reconcileSendCreation } from "./reconcile.js";

describe("pickup recovery", () => {
  it("retries only while the answer is still submitted", () => {
    expect(pickupRecoveryForStatus("submitted")).toBe("retry");
    expect(pickupRecoveryForStatus("picked_up")).toBe("lost");
    expect(pickupRecoveryForStatus("waiting")).toBe("terminal");
  });
});

describe("creation settlement", () => {
  it("keeps polling the exact send status after the 1/2/4 second prefix", async () => {
    const waits: number[] = [];
    let calls = 0;
    const client = {
      sendStatus(): Promise<SendStatusResponse & StateCheckedMetadata> {
        calls += 1;
        if (calls <= 4) return Promise.reject(new ApiFailure("network", false));
        return Promise.resolve({ failedAccessAttempts: 0, releasedAt: [], remainingRetrievals: 1, serverExpiresAt: 1_800_003_600, state: "active", stateCheckedAt: 1_800_000_001 });
      }
    };
    const result = await reconcileSendCreation(client, "locator", "manage-token", 1_800_000_060, (milliseconds) => { waits.push(milliseconds); return Promise.resolve(); });
    expect(result).toEqual({ kind: "created", serverExpiresAt: 1_800_003_600 });
    expect(waits).toEqual([1_000, 2_000, 4_000, 8_000, 8_000]);
    expect(calls).toBe(5);
  });

  it("accepts absence only after a linearized state check past settlement", async () => {
    const settleNotAfter = 1_800_000_060;
    const client = {
      requestStatus(): Promise<RequestStatusResponse & StateCheckedMetadata> {
        return Promise.reject(new ApiFailure("unavailable", false, settleNotAfter + 1));
      }
    };
    await expect(reconcileRequestCreation(client, "locator", "owner-token", settleNotAfter, () => Promise.resolve())).resolves.toEqual({ kind: "absent" });
  });
});
