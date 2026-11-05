import { randomUUID } from "node:crypto";
import { ApiFailure, type KryptexClient } from "@kryptex/client";
import { DEVICE_PERMIT_TTL_SECONDS, type DeviceGrantDays } from "@kryptex/contracts/protocol";
import { encodeBase64Url, randomBytes } from "@kryptex/crypto";
import { forgetDeviceGrant, readDeviceFile, usableDeviceGrant, withDeviceLock, writeDeviceFile, DEVICE_FILE_VERSION } from "./device.js";
import { CliError, errorDetails, type ErrorCode } from "./errors.js";
import type { AuthorizationPhase, DevicePairing, LegacyPairing, OperationRecord, Pairing } from "./record.js";
import { writeRecord } from "./store.js";

export type ExitCode = 0 | 1 | 2 | 3 | 4;

/** Every field of `output` is chosen explicitly by a builder in this package; nothing is copied from state wholesale. */
export interface Outcome {
  readonly exitCode: ExitCode;
  readonly output: Readonly<Record<string, unknown>>;
}

export type NativeClient = Pick<
  KryptexClient,
  | "createRequest"
  | "createSend"
  | "deviceStatus"
  | "mintDevicePermit"
  | "permitStatus"
  | "pickupRequest"
  | "redeemDevicePairing"
  | "redeemPairing"
  | "requestStatus"
  | "revokeDevice"
  | "revokeRequest"
  | "revokeSend"
  | "sendStatus"
  | "startDevicePairing"
  | "startPairing"
>;

export interface FlowContext {
  readonly client: NativeClient;
  readonly deadline: number;
  readonly now: () => number;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly stderr: (chunk: Buffer) => void;
  readonly store: string;
}

export function nowSeconds(context: Pick<FlowContext, "now">): number {
  return Math.floor(context.now() / 1_000);
}

export function save<T extends OperationRecord>(context: Pick<FlowContext, "store">, record: T): T {
  writeRecord(context.store, record);
  return record;
}

export function errorOutcome(handle: string | null, code: ErrorCode): Outcome {
  const details = errorDetails(code);
  return {
    exitCode: 1,
    output: handle === null
      ? { error: code, message: details.message, retryable: details.retryable }
      : { error: code, handle, message: details.message, retryable: details.retryable }
  };
}

/** Maps a failed call that consumed nothing to the CLI's retryable codes; every other API failure is a terminal `unavailable`. */
export function transientError(error: unknown): CliError {
  if (error instanceof ApiFailure && error.code === "rate_limited") return new CliError("rate_limited");
  if (error instanceof ApiFailure && error.code === "quota_exhausted") return new CliError("quota_exhausted");
  if (error instanceof ApiFailure && (error.code === "network" || error.code === "invalid_response" || error.code === "internal_error")) {
    return new CliError("network");
  }
  if (error instanceof CliError) return error;
  return new CliError("unavailable");
}

export function isDevicePairing(pairing: Pairing): pairing is DevicePairing {
  return "deviceToken" in pairing;
}

/** The device pairing page never takes the code from the URL: the person types the code this terminal shows. */
export function pairUrl(origin: string, pairing: Pairing): string {
  return isDevicePairing(pairing) ? `${origin}/pair/device` : `${origin}/pair#${pairing.userCode}`;
}

async function startLegacyPairing(client: NativeClient): Promise<LegacyPairing> {
  const pollToken = encodeBase64Url(randomBytes(32));
  try {
    const started = await client.startPairing({ pollToken });
    return { pairingExpiresAt: started.pairingExpiresAt, pollToken, userCode: started.userCode };
  } catch (error) {
    throw transientError(error);
  }
}

/** Starts a device pairing; a service that predates device grants answers `invalid_request`, and gets a one-permit pairing. */
export async function startPairing(client: NativeClient, maxDays: DeviceGrantDays): Promise<Pairing> {
  const deviceLocator = encodeBase64Url(randomBytes(16));
  const deviceToken = encodeBase64Url(randomBytes(32));
  try {
    const started = await client.startDevicePairing({ deviceLocator, deviceToken, maxDays });
    return { deviceLocator, deviceToken, maxDays, pairingExpiresAt: started.pairingExpiresAt, userCode: started.userCode };
  } catch (error) {
    if (error instanceof ApiFailure && error.code === "invalid_request") return startLegacyPairing(client);
    throw transientError(error);
  }
}

function freshMinting(context: Pick<FlowContext, "now">): AuthorizationPhase {
  return { name: "minting", requestId: randomUUID(), requestedAt: nowSeconds(context) };
}

/** Mints with the device grant when one is usable, and otherwise starts a device pairing. */
export async function nextAuthorization(
  context: Pick<FlowContext, "client" | "now" | "store">,
  record: Pick<OperationRecord, "deviceDays" | "origin">
): Promise<AuthorizationPhase> {
  if (usableDeviceGrant(context.store, record.origin, nowSeconds(context)) !== null) return freshMinting(context);
  return { name: "pairing", pairing: await startPairing(context.client, record.deviceDays) };
}

export function pairingOutcome(record: OperationRecord, pairing: Pairing, exitCode: 3 | 4): Outcome {
  return {
    exitCode,
    output: {
      action: "pair",
      handle: record.handle,
      kind: record.kind,
      pairingExpiresAt: pairing.pairingExpiresAt,
      pairUrl: pairUrl(record.origin, pairing),
      state: "pairing",
      userCode: pairing.userCode
    }
  };
}

type PairingPoll =
  | { readonly kind: "device"; readonly deviceExpiresAt: number }
  | { readonly kind: "expired" }
  | { readonly kind: "pending" }
  | { readonly kind: "permit"; readonly permit: string };

async function redeem(client: NativeClient, pairing: Pairing): Promise<PairingPoll> {
  if (!isDevicePairing(pairing)) {
    const redeemed = await client.redeemPairing({ pollToken: pairing.pollToken, userCode: pairing.userCode });
    return redeemed.state === "approved" ? { kind: "permit", permit: redeemed.permit } : { kind: "pending" };
  }
  const redeemed = await client.redeemDevicePairing({ deviceToken: pairing.deviceToken, userCode: pairing.userCode });
  if (redeemed.state === "transfer") return { kind: "permit", permit: redeemed.permit };
  if (redeemed.state === "device") return { deviceExpiresAt: redeemed.deviceExpiresAt, kind: "device" };
  return { kind: "pending" };
}

/** Polls redemption until the person approves, the pairing expires, or the deadline passes. */
async function pollPairing(context: FlowContext, pairing: Pairing): Promise<PairingPoll> {
  for (;;) {
    if (nowSeconds(context) >= pairing.pairingExpiresAt) return { kind: "expired" };
    try {
      const polled = await redeem(context.client, pairing);
      if (polled.kind !== "pending") return polled;
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "unavailable") return { kind: "expired" };
    }
    const remaining = context.deadline - context.now();
    if (remaining <= 0) return { kind: "pending" };
    await context.sleep(Math.min(3_000, remaining));
  }
}

/** Replays a request ID only while the service still repeats its mint; it measures 120 seconds from the mint, which follows `requestedAt`. */
const MINT_REPLAY_SECONDS = DEVICE_PERMIT_TTL_SECONDS - 30;
/** Bounds mints per command, so a service that keeps rejecting fresh permits cannot drain the quota. */
const MAX_MINTS_PER_RUN = 3;
/** Bounds rejected permits per command for the same reason. */
export const MAX_REJECTED_PERMITS = 2;

export type AuthorizationResult =
  | { readonly kind: "outcome"; readonly outcome: Outcome }
  | { readonly kind: "permit"; readonly permit: string };

/**
 * Advances the pairing and minting phases until the operation holds a permit, a person must act, or the deadline passes.
 * `withAuthorization` builds the record for a phase; each phase is saved before the call it prepares.
 */
export async function authorize<T extends OperationRecord>(
  context: FlowContext,
  initial: T,
  withAuthorization: (phase: AuthorizationPhase) => T
): Promise<AuthorizationResult> {
  let record = initial;
  let mints = 0;
  const mintAgain = (): void => {
    record = save(context, withAuthorization(freshMinting(context)));
  };
  const pairAgain = async (): Promise<AuthorizationResult> => {
    const pairing = await startPairing(context.client, record.deviceDays);
    record = save(context, withAuthorization({ name: "pairing", pairing }));
    return { kind: "outcome", outcome: pairingOutcome(record, pairing, 3) };
  };
  for (;;) {
    const phase = record.phase;
    if (phase.name === "pairing") {
      const polled = await pollPairing(context, phase.pairing);
      if (polled.kind === "pending") return { kind: "outcome", outcome: pairingOutcome(record, phase.pairing, 4) };
      if (polled.kind === "permit") return { kind: "permit", permit: polled.permit };
      if (polled.kind === "expired") {
        if (usableDeviceGrant(context.store, record.origin, nowSeconds(context)) === null) return pairAgain();
        mintAgain();
        continue;
      }
      const pairing = phase.pairing;
      if (!isDevicePairing(pairing)) throw new CliError("internal");
      withDeviceLock(context.store, record.origin, () => {
        if (readDeviceFile(context.store, record.origin).state === "invalid") throw new CliError("state_invalid");
        writeDeviceFile(context.store, {
          deviceExpiresAt: polled.deviceExpiresAt,
          deviceLocator: pairing.deviceLocator,
          deviceToken: pairing.deviceToken,
          origin: record.origin,
          version: DEVICE_FILE_VERSION
        });
      });
      mintAgain();
      continue;
    }
    if (phase.name !== "minting") throw new CliError("internal");
    const grant = usableDeviceGrant(context.store, record.origin, nowSeconds(context));
    if (grant === null) return pairAgain();
    const now = nowSeconds(context);
    if (now < phase.requestedAt || now - phase.requestedAt >= MINT_REPLAY_SECONDS) {
      mintAgain();
      continue;
    }
    mints += 1;
    if (mints > MAX_MINTS_PER_RUN) throw new CliError("network");
    try {
      const minted = await context.client.mintDevicePermit({ deviceLocator: grant.deviceLocator, deviceToken: grant.deviceToken, requestId: phase.requestId });
      return { kind: "permit", permit: minted.permit };
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "creation_permit_required") {
        mintAgain();
        continue;
      }
      if (error instanceof ApiFailure && error.code === "unavailable" && !error.ambiguous) {
        // Only the generic unavailable response means the grant is revoked or expired.
        forgetDeviceGrant(context.store, record.origin, grant.deviceLocator);
        return pairAgain();
      }
      // A lost response keeps the request ID, so the next attempt replays the same mint.
      throw transientError(error);
    }
  }
}

/** Waits up to `milliseconds` without passing the deadline; returns false when no time is left. */
export async function pause(context: FlowContext, milliseconds: number): Promise<boolean> {
  const remaining = context.deadline - context.now();
  if (remaining <= 0) return false;
  await context.sleep(Math.min(milliseconds, remaining));
  return true;
}

/** Thrown by a sleep that would pass the deadline; the operation keeps its state and reports exit 4. */
export class DeadlineReached extends Error {
  constructor() {
    super("deadline reached");
    this.name = "DeadlineReached";
  }
}

export function boundedSleep(context: FlowContext): (milliseconds: number) => Promise<void> {
  return async (milliseconds) => {
    if (!(await pause(context, milliseconds))) throw new DeadlineReached();
  };
}

export function stillWaitingOutcome(record: OperationRecord, state: string): Outcome {
  return { exitCode: 4, output: { handle: record.handle, kind: record.kind, state } };
}
