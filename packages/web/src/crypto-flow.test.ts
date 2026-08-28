import { describe, expect, it } from "vitest";
import type { RequestStatusResponse, SendStatusResponse, StateCheckedMetadata } from "@kryptex/contracts/api";
import { ApiFailure } from "./api-client";
import { checkedResponseExpiry, classifyConsumingFailure, classifyReadFailure, classifySubmitFailure, createFactor, exactEnvelopeForRetry, factorFromInput, pickupRecoveryForStatus, reconcileRequestCreation, reconcileSendCreation, shortenedExpiryRequest, shouldPollRequestStatus } from "./crypto-flow";

describe("factor helpers", () => {
  it("round-trips all three factor modes", async () => {
    const linkOnly = await createFactor("link-only", "", "");
    expect(linkOnly).toMatchObject({ factor: undefined, mode: 0, secondKey: null });
    await expect(factorFromInput(linkOnly.mode, linkOnly.salt, "")).resolves.toBeUndefined();

    const secondKey = await createFactor("second-key", "", "");
    expect(secondKey.mode).toBe(2);
    expect(secondKey.secondKey).not.toBeNull();
    if (secondKey.secondKey === null || secondKey.factor === undefined) throw new Error("Missing generated second key");
    expect(await factorFromInput(secondKey.mode, secondKey.salt, secondKey.secondKey)).toEqual(secondKey.factor);

    const passphrase = "correct horse battery staple";
    const derived = await createFactor("passphrase", passphrase, passphrase);
    expect(derived.mode).toBe(1);
    expect(derived.factor).toBeDefined();
    expect(await factorFromInput(derived.mode, derived.salt, passphrase)).toEqual(derived.factor);
  });
});

describe("safe controller decisions", () => {
  it("accepts shortened response expiry but rejects expansion past the bundle", () => {
    expect(checkedResponseExpiry(1_800_003_600, 1_800_000_900)).toBe(1_800_000_900);
    expect(checkedResponseExpiry(1_800_003_600, 1_800_003_600)).toBe(1_800_003_600);
    expect(() => checkedResponseExpiry(1_800_003_600, 1_800_003_601)).toThrow();
  });

  it("does not construct a shortening request at or behind current time", () => {
    expect(shortenedExpiryRequest(2_000, 1_000)).toBe(1_900);
    expect(shortenedExpiryRequest(1_901, 1_000)).toBe(1_900);
    expect(shortenedExpiryRequest(1_001, 1_000)).toBeNull();
    expect(shortenedExpiryRequest(1_000, 1_000)).toBeNull();
  });

  it("requires explicit recovery for possible consuming and submit outcomes", () => {
    expect(classifyConsumingFailure(new Error("decrypt"), true)).toBe("unknown");
    expect(classifyConsumingFailure(new ApiFailure("network", true), false)).toBe("unknown");
    expect(classifyConsumingFailure(new ApiFailure("unavailable", false), false)).toBe("unavailable");
    expect(classifyConsumingFailure(new ApiFailure("rate_limited", false), false)).toBe("rate_limited");
    expect(classifyConsumingFailure(new ApiFailure("rate_limited", false), true)).toBe("unknown");
    expect(classifyReadFailure(new ApiFailure("rate_limited", false))).toBe("rate_limited");
    expect(classifyReadFailure(new Error("decrypt"))).toBe("unavailable");
    expect(classifySubmitFailure(new ApiFailure("unavailable", false))).toBe("unknown");
    expect(classifySubmitFailure(new ApiFailure("invalid_request", false))).toBe("unavailable");
    expect(pickupRecoveryForStatus("submitted")).toBe("retry");
    expect(pickupRecoveryForStatus("picked_up")).toBe("lost");
    expect(pickupRecoveryForStatus("waiting")).toBe("terminal");
  });

  it("polls the pickup status only while an unanswered request needs nothing from the owner", () => {
    expect(shouldPollRequestStatus(true, false, "waiting")).toBe(true);
    expect(shouldPollRequestStatus(true, false, "submitted")).toBe(false);
    expect(shouldPollRequestStatus(true, false, "picked_up")).toBe(false);
    expect(shouldPollRequestStatus(true, false, "revoked")).toBe(false);
    expect(shouldPollRequestStatus(true, false, "expired")).toBe(false);
    expect(shouldPollRequestStatus(true, false, null)).toBe(false);
    expect(shouldPollRequestStatus(false, false, "waiting")).toBe(false);
    expect(shouldPollRequestStatus(true, true, "waiting")).toBe(false);
  });

  it("reuses the exact response envelope after its first creation", async () => {
    let creations = 0;
    const create = (): Promise<string> => { creations += 1; return Promise.resolve("exact-kxr1"); };
    const first = await exactEnvelopeForRetry(null, create);
    const retry = await exactEnvelopeForRetry(first, create);
    expect(first).toBe("exact-kxr1");
    expect(retry).toBe(first);
    expect(creations).toBe(1);
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
