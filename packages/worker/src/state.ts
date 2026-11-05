import type { CapabilityKind, DeviceGrantDays, FactorMode } from "@kryptex/contracts/protocol";

export interface ObjectMetadata {
  readonly digest: string;
  readonly key: string;
  readonly length: number;
}

export interface AuthLease {
  readonly attemptId: string;
  readonly authBusyUntil: number;
  readonly failureCount: number;
  readonly nextAuthAt: number;
}

interface ResourceRecord {
  readonly authKeyId: string;
  readonly cleanupFailureCount: number;
  readonly failedAccessAttempts: number;
  readonly generation: number;
  readonly nextCleanupAt: number | null;
  readonly pendingKeys: readonly string[];
  readonly serverExpiresAt: number;
}

export interface SendRecord extends ResourceRecord {
  readonly attemptId: string | null;
  readonly clientNotAfter: number | null;
  readonly factorMode: FactorMode;
  readonly kind: "send";
  readonly manageTag: string;
  readonly maxRetrievals: number;
  readonly object: ObjectMetadata | null;
  readonly releasedAt: readonly number[];
  readonly remainingRetrievals: number;
  readonly retrieveTag: string | null;
  readonly state: "active" | "exhausted" | "revoked" | "expired";
}

export interface RequestRecord extends ResourceRecord {
  readonly attemptId: string | null;
  readonly clientNotAfter: number | null;
  readonly factorMode: FactorMode;
  readonly kind: "request";
  readonly ownerTag: string;
  readonly responseAttemptId: string | null;
  readonly responseObject: ObjectMetadata | null;
  readonly schemaDigest: string | null;
  readonly schemaObject: ObjectMetadata | null;
  readonly state: "waiting" | "submitted" | "picked_up" | "revoked" | "expired";
  readonly writeTag: string | null;
}

export interface PermitRecord {
  readonly authKeyId: string;
  readonly createdAt: number;
  readonly generation: number;
  readonly kind: "permit";
  readonly permitExpiresAt: number;
  readonly state: "unused" | "consumed";
  readonly tag: string;
}

export interface PermitIssuanceRecord {
  readonly keyId: string;
  readonly kind: "permit_issuance";
  readonly retainUntil: number;
}

export interface PairingApproval {
  readonly keyId: string;
  readonly permitExpiresAt: number;
  readonly requestId: string;
}

export interface PairingRecord {
  readonly approval: PairingApproval | null;
  readonly authKeyId: string;
  readonly generation: number;
  readonly kind: "pairing";
  readonly pairingExpiresAt: number;
  readonly tag: string;
}

export interface DevicePairingApproval extends PairingApproval {
  readonly claimTag: string;
}

export type DevicePairingClaim =
  | { readonly claimedAt: number; readonly scope: "transfer" }
  | {
      readonly claimedAt: number;
      readonly days: DeviceGrantDays;
      readonly deviceExpiresAt: number;
      readonly manageTag: string;
      readonly scope: "device";
      readonly state: "claiming" | "claimed";
    };

export interface DevicePairingRecord {
  readonly approval: DevicePairingApproval | null;
  readonly authKeyId: string;
  readonly claim: DevicePairingClaim | null;
  readonly deviceLocator: string;
  readonly generation: number;
  /** The device-token tag for the future grant, computed while the device token is at hand. */
  readonly grantTag: string;
  readonly kind: "device_pairing";
  readonly maxDays: DeviceGrantDays;
  readonly pairingExpiresAt: number;
  readonly pollTag: string;
}

export interface DeviceMint {
  readonly keyId: string;
  readonly mintedAt: number;
  readonly requestId: string;
}

export interface HourlyMintCount {
  readonly count: number;
  /** Whole UTC hours since the Unix epoch. */
  readonly hour: number;
}

export interface DeviceRecord {
  readonly authKeyId: string;
  readonly deviceTag: string;
  readonly expiresAt: number;
  readonly generation: number;
  readonly hourlyMints: readonly HourlyMintCount[];
  readonly kind: "device";
  readonly manageTag: string;
  /** Only mints still inside the device-permit lifetime keep their time; older IDs live on as spent keys. */
  readonly recentMints: readonly DeviceMint[];
  readonly revoked: boolean;
}

export interface CapabilitySnapshot {
  readonly generation: number;
  readonly keyId: string;
  readonly tag: string;
}

export type AuthResult =
  | { readonly kind: "authorized"; readonly snapshot: CapabilitySnapshot }
  | { readonly kind: "rate_limited" }
  | { readonly kind: "unavailable"; readonly stateCheckedAt: number };

export const RECORD_KEY = "record";
export function authKey(capabilityKind: CapabilityKind): string {
  return `auth:${capabilityKind}`;
}

export function spentRequestKey(requestId: string): string {
  return `spent:${requestId}`;
}

export function cleanupDelayMs(failureCount: number): number {
  return Math.min(2_000 * 2 ** Math.max(0, failureCount - 1), 300_000);
}

export async function recordCleanupFailure(
  storage: DurableObjectStorage,
  keys: readonly string[],
  expired: boolean,
  clock: () => number
): Promise<void> {
  await storage.transaction(async (transaction) => {
    const current = await transaction.get<SendRecord | RequestRecord>(RECORD_KEY);
    if (current === undefined) {
      return;
    }
    const failureCount = Math.min(current.cleanupFailureCount + 1, 8);
    const nowMs = clock();
    const nextCleanupAt = expired
      ? nowMs + cleanupDelayMs(failureCount)
      : Math.min(nowMs + cleanupDelayMs(failureCount), current.serverExpiresAt * 1_000);
    const pendingKeys = [...new Set([...current.pendingKeys, ...keys])];
    const failed = current.kind === "send"
      ? { ...current, cleanupFailureCount: failureCount, generation: current.generation + 1, nextCleanupAt, pendingKeys }
      : { ...current, cleanupFailureCount: failureCount, generation: current.generation + 1, nextCleanupAt, pendingKeys };
    await transaction.put(RECORD_KEY, failed);
    await transaction.setAlarm(nextCleanupAt);
  });
}

export const AUTH_FAILURE_SATURATION = 15;
const AUTH_DELAY_CAP_MS = 30_000;
const GUESSABLE_AUTH_DELAY_CAP_MS = 3_600_000;

/** A longer cap applies where online guessing is feasible: a passphrase-derived retrieve or write token. */
export function authDelayMs(failureCount: number, guessable: boolean): number {
  return Math.min(250 * 2 ** Math.max(0, failureCount - 1), guessable ? GUESSABLE_AUTH_DELAY_CAP_MS : AUTH_DELAY_CAP_MS);
}
