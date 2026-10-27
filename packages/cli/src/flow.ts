import { ApiFailure, type KryptexClient } from "@kryptex/client";
import { encodeBase64Url, randomBytes } from "@kryptex/crypto";
import { CliError, errorDetails, type ErrorCode } from "./errors.js";
import type { OperationRecord, Pairing } from "./record.js";
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
  | "permitStatus"
  | "pickupRequest"
  | "redeemPairing"
  | "requestStatus"
  | "revokeRequest"
  | "revokeSend"
  | "sendStatus"
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
  if (error instanceof ApiFailure && (error.code === "network" || error.code === "invalid_response" || error.code === "internal_error")) {
    return new CliError("network");
  }
  if (error instanceof CliError) return error;
  return new CliError("unavailable");
}

export function pairUrl(origin: string, userCode: string): string {
  return `${origin}/pair#${userCode}`;
}

export async function startPairing(client: NativeClient): Promise<Pairing> {
  const pollToken = encodeBase64Url(randomBytes(32));
  try {
    const started = await client.startPairing({ pollToken });
    return { pairingExpiresAt: started.pairingExpiresAt, pollToken, userCode: started.userCode };
  } catch (error) {
    throw transientError(error);
  }
}

export function pairingOutcome(record: OperationRecord, pairing: Pairing, exitCode: 3 | 4): Outcome {
  return {
    exitCode,
    output: {
      action: "pair",
      handle: record.handle,
      kind: record.kind,
      pairingExpiresAt: pairing.pairingExpiresAt,
      pairUrl: pairUrl(record.origin, pairing.userCode),
      state: "pairing",
      userCode: pairing.userCode
    }
  };
}

export type PairingPoll =
  | { readonly kind: "approved"; readonly permit: string }
  | { readonly kind: "expired" }
  | { readonly kind: "pending" };

/** Polls redemption until the person approves, the pairing expires, or the deadline passes. */
export async function pollPairing(context: FlowContext, pairing: Pairing): Promise<PairingPoll> {
  for (;;) {
    if (nowSeconds(context) >= pairing.pairingExpiresAt) return { kind: "expired" };
    try {
      const redeemed = await context.client.redeemPairing({ pollToken: pairing.pollToken, userCode: pairing.userCode });
      if (redeemed.state === "approved") return { kind: "approved", permit: redeemed.permit };
    } catch (error) {
      if (error instanceof ApiFailure && error.code === "unavailable") return { kind: "expired" };
    }
    const remaining = context.deadline - context.now();
    if (remaining <= 0) return { kind: "pending" };
    await context.sleep(Math.min(3_000, remaining));
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
