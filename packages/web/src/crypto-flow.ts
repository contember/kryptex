import type { FactorMode } from "@kryptex/contracts/protocol";
import type { RequestStatusResponse } from "@kryptex/contracts/api";
import {
  decodeBundle,
  decodeRandomFactor,
  deriveConfirmedPassphraseFactor,
  derivePassphraseFactor,
  deriveRandomFactor,
  encodeBundle,
  encodeRandomFactor,
  randomBytes,
  strictUtf8,
  type KryptexBundle
} from "@kryptex/crypto";
import { ApiFailure, type KryptexClient } from "./api-client";
import type { FragmentCapture } from "./fragment";
import type { Protection } from "./ui";

export interface FactorMaterial {
  readonly factor: Uint8Array<ArrayBuffer> | undefined;
  readonly mode: FactorMode;
  readonly salt: Uint8Array<ArrayBuffer>;
  readonly secondKey: string | null;
}

export async function createFactor(
  protection: Protection,
  passphrase: string,
  confirmation: string
): Promise<FactorMaterial> {
  if (protection === "link-only") {
    return { factor: undefined, mode: 0, salt: new Uint8Array(16), secondKey: null };
  }
  if (protection === "second-key") {
    const secret = randomBytes(16);
    return { factor: await deriveRandomFactor(secret), mode: 2, salt: new Uint8Array(16), secondKey: encodeRandomFactor(secret) };
  }
  const salt = randomBytes(16);
  return {
    factor: await deriveConfirmedPassphraseFactor(passphrase, confirmation, salt),
    mode: 1,
    salt,
    secondKey: null
  };
}

export async function factorFromInput(mode: FactorMode, salt: Uint8Array, value: string): Promise<Uint8Array<ArrayBuffer> | undefined> {
  if (mode === 0) return undefined;
  return mode === 1 ? derivePassphraseFactor(value, salt) : deriveRandomFactor(decodeRandomFactor(value));
}

const bundleCache = new WeakMap<FragmentCapture, KryptexBundle | null>();

export function consumeBundle(capture: FragmentCapture, expectedKind: 1 | 2 | 3 | 4): KryptexBundle | null {
  const cached = bundleCache.get(capture);
  if (cached !== undefined) return cached?.kind === expectedKind ? cached : null;
  const fragment = capture.fragmentBytes;
  if (fragment === null) {
    bundleCache.set(capture, null);
    return null;
  }
  try {
    const bundle = decodeBundle(strictUtf8(fragment));
    bundleCache.set(capture, bundle);
    return bundle.kind === expectedKind ? bundle : null;
  } catch {
    bundleCache.set(capture, null);
    return null;
  } finally {
    fragment.fill(0);
  }
}

export function artifactUrl(path: "/s" | "/m" | "/r" | "/i", bundle: KryptexBundle, origin = window.location.origin): string {
  return `${new URL(path, origin).href}#${encodeBundle(bundle)}`;
}

export function requestFieldId(index: number): string {
  return `field${String(index + 1).padStart(3, "0")}`;
}

export function checkedResponseExpiry(bundleExpiresAt: number, responseExpiresAt: number): number {
  if (!Number.isSafeInteger(bundleExpiresAt) || bundleExpiresAt < 0 || !Number.isSafeInteger(responseExpiresAt) || responseExpiresAt < 0 || responseExpiresAt > bundleExpiresAt) {
    throw new Error("Response expiry exceeds the link bound");
  }
  return responseExpiresAt;
}

export function shortenedExpiryRequest(currentExpiresAt: number, nowSeconds: number): number | null {
  if (!Number.isSafeInteger(currentExpiresAt) || !Number.isSafeInteger(nowSeconds) || currentExpiresAt <= nowSeconds + 1) return null;
  return Math.min(currentExpiresAt - 1, nowSeconds + 900);
}

export function classifyConsumingFailure(error: unknown, responseReleased: boolean): "unknown" | "unavailable" | "rate_limited" {
  if (responseReleased || error instanceof ApiFailure && error.ambiguous) return "unknown";
  return classifyReadFailure(error);
}

export function classifyReadFailure(error: unknown): "unavailable" | "rate_limited" {
  return error instanceof ApiFailure && error.code === "rate_limited" ? "rate_limited" : "unavailable";
}

export function classifySubmitFailure(error: unknown): "unknown" | "unavailable" {
  if (error instanceof ApiFailure && (error.ambiguous || error.code === "unavailable")) return "unknown";
  return "unavailable";
}

export function pickupRecoveryForStatus(state: RequestStatusResponse["state"]): "retry" | "lost" | "terminal" {
  if (state === "submitted") return "retry";
  if (state === "picked_up") return "lost";
  return "terminal";
}

export async function exactEnvelopeForRetry(existing: string | null, create: () => Promise<string>): Promise<string> {
  if (existing !== null) return existing;
  return create();
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
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}
