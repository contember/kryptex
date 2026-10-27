import type { RequestStatusResponse } from "@kryptex/contracts/api";
import { ApiFailure, type KryptexClient } from "./api-client.js";

export function pickupRecoveryForStatus(state: RequestStatusResponse["state"]): "retry" | "lost" | "terminal" {
  if (state === "submitted") return "retry";
  if (state === "picked_up") return "lost";
  return "terminal";
}

export async function reconcileSendCreation(
  client: Pick<KryptexClient, "sendStatus">,
  locator: string,
  manageToken: string,
  settleNotAfter: number,
  wait: (milliseconds: number) => Promise<void> = delay
): Promise<{ readonly kind: "created"; readonly serverExpiresAt: number } | { readonly kind: "absent" }> {
  for (const milliseconds of [1_000, 2_000, 4_000]) {
    await wait(milliseconds);
    try {
      const status = await client.sendStatus({ locator, manageToken });
      return { kind: "created", serverExpiresAt: status.serverExpiresAt };
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "unavailable" && error.stateCheckedAt !== null && error.stateCheckedAt > settleNotAfter) {
        return { kind: "absent" };
      }
    }
  }
  for (;;) {
    await wait(8_000);
    try {
      const status = await client.sendStatus({ locator, manageToken });
      return { kind: "created", serverExpiresAt: status.serverExpiresAt };
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "unavailable" && error.stateCheckedAt !== null && error.stateCheckedAt > settleNotAfter) return { kind: "absent" };
    }
  }
}

export async function reconcileRequestCreation(
  client: Pick<KryptexClient, "requestStatus">,
  locator: string,
  ownerToken: string,
  settleNotAfter: number,
  wait: (milliseconds: number) => Promise<void> = delay
): Promise<{ readonly kind: "created"; readonly serverExpiresAt: number } | { readonly kind: "absent" }> {
  for (const milliseconds of [1_000, 2_000, 4_000]) {
    await wait(milliseconds);
    try {
      const status = await client.requestStatus({ locator, ownerToken });
      return { kind: "created", serverExpiresAt: status.serverExpiresAt };
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "unavailable" && error.stateCheckedAt !== null && error.stateCheckedAt > settleNotAfter) {
        return { kind: "absent" };
      }
    }
  }
  for (;;) {
    await wait(8_000);
    try {
      const status = await client.requestStatus({ locator, ownerToken });
      return { kind: "created", serverExpiresAt: status.serverExpiresAt };
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "unavailable" && error.stateCheckedAt !== null && error.stateCheckedAt > settleNotAfter) return { kind: "absent" };
    }
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
