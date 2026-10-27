import { FAILED_ACCESS_SATURATION } from "@kryptex/contracts/protocol";
import { decodeCanonicalBase64Url } from "./strict.js";
import {
  AUTH_FAILURE_SATURATION,
  RECORD_KEY,
  authDelayMs,
  authKey,
  type AuthLease,
  type AuthResult,
  type CapabilitySnapshot,
  type PairingRecord,
  type PermitRecord,
  type RequestRecord,
  type SendRecord
} from "./state.js";
import { randomBase64Url, unixSeconds, verifyCapabilityTag, ZERO_TAG } from "./core.js";
import type { CheckedWorkerEnvironment } from "./env.js";

type StoredRecord = SendRecord | RequestRecord | PermitRecord | PairingRecord;

interface AuthenticationInput {
  readonly capabilityKind: 1 | 2 | 3 | 4;
  readonly locator: Uint8Array;
  readonly resourceKind: 1 | 2 | 3 | 4;
  readonly token: Uint8Array;
}

export interface AuthenticationReservation {
  readonly attemptId: string;
  readonly snapshot: CapabilitySnapshot;
  readonly stateCheckedAt: number;
}

export type ReservationResult =
  | { readonly kind: "rate_limited" }
  | { readonly kind: "reserved"; readonly reservation: AuthenticationReservation };

function snapshotFor(record: StoredRecord | undefined, capabilityKind: 1 | 2 | 3 | 4, activeKeyId: string): CapabilitySnapshot {
  if (record === undefined) {
    return { generation: -1, keyId: activeKeyId, tag: ZERO_TAG };
  }
  if (record.kind === "send") {
    return {
      generation: record.generation,
      keyId: record.authKeyId,
      tag: capabilityKind === 1 ? record.retrieveTag ?? ZERO_TAG : record.manageTag
    };
  }
  if (record.kind === "request") {
    return {
      generation: record.generation,
      keyId: record.authKeyId,
      tag: capabilityKind === 1 ? record.writeTag ?? ZERO_TAG : record.ownerTag
    };
  }
  return { generation: record.generation, keyId: record.authKeyId, tag: record.tag };
}

/** Counts only a wrong access token, so a lost race never reads to the owner as someone probing the link. */
function withFailedAccess(record: StoredRecord): StoredRecord | null {
  if (record.kind === "permit" || record.kind === "pairing" || record.failedAccessAttempts >= FAILED_ACCESS_SATURATION) {
    return null;
  }
  return { ...record, failedAccessAttempts: record.failedAccessAttempts + 1 };
}

/** Only a passphrase-derived retrieve or write token can be guessed online; every other token is 128 bits or more of randomness. */
function guessableCapability(record: StoredRecord | undefined, capabilityKind: 1 | 2 | 3 | 4): boolean {
  return capabilityKind === 1 && (record?.kind === "send" || record?.kind === "request") && record.factorMode === 1;
}

function currentTag(record: StoredRecord | undefined, capabilityKind: 1 | 2 | 3 | 4): string | null | undefined {
  if (record === undefined) {
    return undefined;
  }
  if (record.kind === "send") {
    return capabilityKind === 1 ? record.retrieveTag : record.manageTag;
  }
  if (record.kind === "request") {
    return capabilityKind === 1 ? record.writeTag : record.ownerTag;
  }
  return record.tag;
}

export async function authenticate(
  storage: DurableObjectStorage,
  environment: CheckedWorkerEnvironment,
  input: AuthenticationInput
): Promise<AuthResult> {
  const attemptId = randomBase64Url(16);
  const result = reserveAuthentication(
    storage,
    input.capabilityKind,
    environment.activeCapabilityKeyId,
    attemptId,
    Date.now
  );

  if (result.kind === "rate_limited") {
    return { kind: "rate_limited" };
  }
  const reservation = result.reservation;
  const key = environment.capabilityKeys.get(reservation.snapshot.keyId);
  let verified = false;
  if (key !== undefined) {
    try {
      verified = await verifyCapabilityTag(
        key,
        reservation.snapshot.tag,
        input.resourceKind,
        input.capabilityKind,
        input.locator,
        input.token
      );
    } catch {
      verified = false;
    }
  }

  return finishAuthentication(storage, input.capabilityKind, reservation, verified, Date.now);
}

export function reserveAuthentication(
  storage: DurableObjectStorage,
  capabilityKind: 1 | 2 | 3 | 4,
  activeKeyId: string,
  attemptId: string,
  clock: () => number
): ReservationResult {
  return storage.transactionSync<ReservationResult>(() => {
    const nowMs = clock();
    const key = authKey(capabilityKind);
    const lease = storage.kv.get<AuthLease>(key);
    if (lease !== undefined && (lease.authBusyUntil > nowMs || lease.nextAuthAt > nowMs)) {
      return { kind: "rate_limited" };
    }
    const failureCount = lease?.failureCount ?? 0;
    storage.kv.put<AuthLease>(key, {
      attemptId,
      authBusyUntil: nowMs + 5_000,
      failureCount,
      nextAuthAt: lease?.nextAuthAt ?? 0
    });
    const record = storage.kv.get<StoredRecord>(RECORD_KEY);
    return {
      kind: "reserved",
      reservation: {
        attemptId,
        snapshot: snapshotFor(record, capabilityKind, activeKeyId),
        stateCheckedAt: unixSeconds(nowMs)
      }
    };
  });
}

export function finishAuthentication(
  storage: DurableObjectStorage,
  capabilityKind: 1 | 2 | 3 | 4,
  reservation: AuthenticationReservation,
  verified: boolean,
  clock: () => number
): AuthResult {
  return storage.transactionSync<AuthResult>(() => {
    const key = authKey(capabilityKind);
    const lease = storage.kv.get<AuthLease>(key);
    if (lease?.attemptId !== reservation.attemptId) {
      return { kind: "unavailable", stateCheckedAt: reservation.stateCheckedAt };
    }
    const record = storage.kv.get<StoredRecord>(RECORD_KEY);
    const tag = currentTag(record, capabilityKind);
    const snapshotStillMatches =
      record?.generation === reservation.snapshot.generation &&
      record.authKeyId === reservation.snapshot.keyId &&
      tag === reservation.snapshot.tag;
    if (!verified || !snapshotStillMatches) {
      if (!verified && capabilityKind === 1 && record !== undefined) {
        const counted = withFailedAccess(record);
        if (counted !== null) {
          // Deliberately keeps the generation, so counting a failure never invalidates a concurrent reservation.
          storage.kv.put<StoredRecord>(RECORD_KEY, counted);
        }
      }
      const failureCount = Math.min(lease.failureCount + 1, AUTH_FAILURE_SATURATION);
      const nowMs = clock();
      storage.kv.put<AuthLease>(key, {
        attemptId: "",
        authBusyUntil: 0,
        failureCount,
        nextAuthAt: nowMs + authDelayMs(failureCount, guessableCapability(record, capabilityKind))
      });
      return {
        kind: "unavailable",
        stateCheckedAt: reservation.snapshot.generation === -1 ? reservation.stateCheckedAt : unixSeconds(nowMs)
      };
    }
    storage.kv.put<AuthLease>(key, {
      attemptId: "",
      authBusyUntil: 0,
      failureCount: 0,
      nextAuthAt: 0
    });
    return { kind: "authorized", snapshot: reservation.snapshot };
  });
}

export function decodeAuthInput(locator: string, token: string): { readonly locator: Uint8Array; readonly token: Uint8Array } {
  return {
    locator: decodeCanonicalBase64Url(locator, 16, "locator"),
    token: decodeCanonicalBase64Url(token, 32, "capability token")
  };
}
