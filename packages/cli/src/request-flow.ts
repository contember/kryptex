import { createHash } from "node:crypto";
import { basename } from "node:path";
import { ApiFailure, pickupRecoveryForStatus, reconcileRequestCreation } from "@kryptex/client";
import type { RequestState } from "@kryptex/contracts/api";
import type { RequestSchemaField, RequestSchemaPayload } from "@kryptex/contracts/payloads";
import {
  decodeBase64Url,
  deriveHpkeKeyPair,
  deriveRequestOwnerKeys,
  deriveRequestWriteKeys,
  encodeBase64Url,
  encodeBundle,
  encryptRequestSchemaEnvelope,
  equalBytes,
  KryptexCryptoError,
  openRequestResponse,
  parseKxe1Header,
  parseKxr1Header,
  randomBytes,
  receiptDisplay
} from "@kryptex/crypto";
import { checkDotenvTargets, upsertDotenv } from "./dotenv.js";
import { CliError, type ErrorCode } from "./errors.js";
import { runRedacted } from "./exec.js";
import {
  boundedSleep,
  DeadlineReached,
  errorOutcome,
  nowSeconds,
  pairingOutcome,
  pause,
  pollPairing,
  save,
  startPairing,
  stillWaitingOutcome,
  transientError,
  type FlowContext,
  type Outcome
} from "./flow.js";
import { checkProjectPath, readProjectFile, replaceProjectFile } from "./project.js";
import type { CreatedRequest, Delivered, RequestAttempt, RequestPhase, RequestRecord, RequestSink, StoredField } from "./record.js";
import { acquireLock } from "./store.js";

function withPhase(record: RequestRecord, phase: RequestPhase): RequestRecord {
  return { ...record, phase };
}

function failed(context: FlowContext, record: RequestRecord, error: ErrorCode): Outcome {
  save(context, withPhase(record, { error, name: "failed" }));
  return errorOutcome(record.handle, error);
}

export function schemaPayload(record: Pick<RequestRecord, "fields" | "title">, publicKey: Uint8Array): RequestSchemaPayload {
  const fields: RequestSchemaField[] = record.fields.map((entry) => ({
    help: entry.help,
    id: entry.id,
    label: entry.label,
    required: entry.required,
    type: entry.type
  }));
  return { fields, kind: "request-schema", recipientPublicKey: encodeBase64Url(publicKey), title: record.title };
}

async function ownerToken(request: Pick<CreatedRequest, "ownerSeed">): Promise<string> {
  return encodeBase64Url((await deriveRequestOwnerKeys(decodeBase64Url(request.ownerSeed))).ownerToken);
}

export async function writeUrl(origin: string, request: CreatedRequest): Promise<string> {
  const owner = await deriveRequestOwnerKeys(decodeBase64Url(request.ownerSeed));
  const pair = await deriveHpkeKeyPair(owner.hpkeIkm);
  const bundle = encodeBundle({
    factorMode: 0,
    kind: 3,
    recipientPublicKey: pair.publicKey,
    requestLocator: decodeBase64Url(request.locator),
    salt: new Uint8Array(16),
    serverExpiresAt: request.serverExpiresAt,
    writeSeed: decodeBase64Url(request.writeSeed)
  });
  return `${origin}/r#${bundle}`;
}

async function waitingOutcome(record: RequestRecord, request: CreatedRequest, exitCode: 3 | 4): Promise<Outcome> {
  const output = {
    expiresAt: request.serverExpiresAt,
    handle: record.handle,
    kind: record.kind,
    state: "waiting",
    writeUrl: await writeUrl(record.origin, request)
  };
  return { exitCode, output: exitCode === 3 ? { action: "hand_over_write_link", ...output } : output };
}

function deliveredOutcome(record: RequestRecord, delivered: Delivered, receipt: string): Outcome {
  const summary = delivered.kind === "env"
    ? { keys: delivered.keys, path: delivered.path }
    : { command: delivered.command, exitCode: delivered.exitCode, keys: delivered.keys };
  return { exitCode: 0, output: { delivered: summary, handle: record.handle, kind: record.kind, receipt, state: "delivered" } };
}

function targets(fields: readonly StoredField[]): readonly string[] {
  return fields.flatMap((entry) => entry.target === null ? [] : [entry.target]);
}

/** Confirms the output can take the answer before anything consumes it on the service. */
export function preflightSink(record: RequestRecord): void {
  if (record.sink.kind !== "env") return;
  const absolute = checkProjectPath(record.projectRoot, record.sink.path, { existence: "either", output: true });
  const existing = readProjectFile(absolute);
  if (existing !== null) checkDotenvTargets(existing, targets(record.fields));
}

function destinationLockName(record: RequestRecord, sink: Extract<RequestSink, { readonly kind: "env" }>): string {
  return `dest-${createHash("sha256").update(`${record.projectRoot}\0${sink.path}`).digest("hex")}`;
}

async function deliver(context: FlowContext, record: RequestRecord, values: ReadonlyMap<string, string>): Promise<Delivered> {
  if (record.sink.kind === "env") {
    const sink = record.sink;
    // An optional field left empty keeps whatever the file already assigns.
    const answered = new Map([...values].filter(([, value]) => value.length > 0));
    const release = acquireLock(context.store, destinationLockName(record, sink));
    try {
      const absolute = checkProjectPath(record.projectRoot, sink.path, { existence: "either", output: true });
      replaceProjectFile(absolute, upsertDotenv(readProjectFile(absolute) ?? "", answered, sink.dialect));
    } finally {
      release();
    }
    return { keys: [...answered.keys()], kind: "env", path: sink.path };
  }
  const keys = [...values.keys()];
  const environment = Object.fromEntries(values);
  const result = await runRedacted(
    record.sink.argv,
    record.cwd,
    environment,
    [...values].map(([target, value]) => ({ target, value })),
    context.stderr
  );
  if (result.exitCode !== 0) throw new CliError("exec_failed");
  return { command: basename(record.sink.argv[0] ?? ""), exitCode: 0, keys, kind: "exec" };
}

/** Opens the stored answer with the stored owner seed and maps it by the stored field IDs, never by returned labels. */
async function openAnswer(context: FlowContext, record: RequestRecord, request: CreatedRequest, response: Uint8Array): Promise<ReadonlyMap<string, string>> {
  const header = parseKxr1Header(response);
  if (header.clientNotAfter !== request.clientNotAfter || !equalBytes(header.schemaDigest, decodeBase64Url(request.schemaDigest))) {
    throw new CliError("answer_invalid");
  }
  const owner = await deriveRequestOwnerKeys(decodeBase64Url(request.ownerSeed));
  const opened = await openRequestResponse({
    envelope: response,
    expectedClientNotAfter: request.clientNotAfter,
    hpkeIkm: owner.hpkeIkm,
    nowSeconds: nowSeconds(context),
    requestLocator: decodeBase64Url(request.locator),
    serverExpiresAt: request.serverExpiresAt
  });
  const values = new Map<string, string>();
  for (const entry of record.fields) {
    if (entry.target === null) continue;
    const answer = opened.payload.answers.find((candidate) => candidate.id === entry.id);
    if (answer === undefined) throw new CliError("answer_invalid");
    values.set(entry.target, answer.value);
  }
  return values;
}

function terminalError(state: RequestState): ErrorCode {
  if (state === "picked_up") return "pickup_lost";
  if (state === "revoked") return "revoked";
  if (state === "expired") return "expired";
  return "unavailable";
}

async function buildAttempt(record: RequestRecord, serverTime: number): Promise<RequestAttempt> {
  const locator = randomBytes(16);
  const writeSeed = randomBytes(32);
  const ownerSeed = randomBytes(32);
  const [writeKeys, ownerKeys] = await Promise.all([deriveRequestWriteKeys(writeSeed, 0), deriveRequestOwnerKeys(ownerSeed)]);
  const pair = await deriveHpkeKeyPair(ownerKeys.hpkeIkm);
  const clientNotAfter = serverTime + record.ttl;
  const envelope = await encryptRequestSchemaEnvelope({
    clientNotAfter,
    factorMode: 0,
    payload: schemaPayload(record, pair.publicKey),
    schemaKey: writeKeys.schemaKey
  });
  return {
    attemptId: encodeBase64Url(randomBytes(16)),
    clientNotAfter,
    envelope: encodeBase64Url(envelope),
    locator: encodeBase64Url(locator),
    ownerSeed: encodeBase64Url(ownerSeed),
    schemaDigest: encodeBase64Url(parseKxe1Header(envelope).schemaDigest),
    settleNotAfter: serverTime + 60,
    writeSeed: encodeBase64Url(writeSeed)
  };
}

function createdFromAttempt(attempt: RequestAttempt, serverExpiresAt: number): CreatedRequest {
  return {
    clientNotAfter: attempt.clientNotAfter,
    locator: attempt.locator,
    ownerSeed: attempt.ownerSeed,
    schemaDigest: attempt.schemaDigest,
    serverExpiresAt,
    writeSeed: attempt.writeSeed
  };
}

async function restartPairing(context: FlowContext, record: RequestRecord): Promise<Outcome> {
  const pairing = await startPairing(context.client);
  const next = save(context, withPhase(record, { name: "pairing", pairing }));
  return pairingOutcome(next, pairing, 3);
}

/** Advances a request until a person must act, it finishes, or the deadline passes. See "Request lifecycle" in docs/spec/cli-v1.md. */
export async function advanceRequest(context: FlowContext, initial: RequestRecord): Promise<Outcome> {
  let record = initial;
  let statusDelay = 2_000;
  let pickupRetried = false;
  for (;;) {
    const phase = record.phase;
    switch (phase.name) {
      case "pairing": {
        const polled = await pollPairing(context, phase.pairing);
        if (polled.kind === "expired") return restartPairing(context, record);
        if (polled.kind === "pending") return pairingOutcome(record, phase.pairing, 4);
        record = save(context, withPhase(record, { attempt: null, name: "creating", permit: polled.permit }));
        break;
      }
      case "creating": {
        if (phase.attempt !== null) {
          const attempt = phase.attempt;
          let reconciled: Awaited<ReturnType<typeof reconcileRequestCreation>>;
          try {
            reconciled = await reconcileRequestCreation(context.client, attempt.locator, await ownerToken(attempt), attempt.settleNotAfter, boundedSleep(context));
          } catch (error) {
            if (error instanceof DeadlineReached) return stillWaitingOutcome(record, "creating");
            throw error;
          }
          record = save(context, withPhase(record, reconciled.kind === "created"
            ? { name: "waiting", reported: false, request: createdFromAttempt(attempt, reconciled.serverExpiresAt) }
            : { attempt: null, name: "creating", permit: phase.permit }));
          break;
        }
        let serverTime: number;
        try {
          serverTime = (await context.client.permitStatus(phase.permit)).serverTime;
        } catch (error) {
          if (error instanceof ApiFailure && error.code === "creation_permit_required") return restartPairing(context, record);
          throw transientError(error);
        }
        const attempt = await buildAttempt(record, serverTime);
        record = save(context, withPhase(record, { attempt, name: "creating", permit: phase.permit }));
        try {
          const created = await context.client.createRequest({
            attemptId: attempt.attemptId,
            clientNotAfter: attempt.clientNotAfter,
            envelope: attempt.envelope,
            locator: attempt.locator,
            ownerToken: await ownerToken(attempt),
            settleNotAfter: attempt.settleNotAfter,
            ttlSeconds: record.ttl,
            writeToken: encodeBase64Url((await deriveRequestWriteKeys(decodeBase64Url(attempt.writeSeed), 0)).writeToken)
          }, phase.permit);
          record = save(context, withPhase(record, { name: "waiting", reported: false, request: createdFromAttempt(attempt, created.serverExpiresAt) }));
        } catch (error) {
          if (error instanceof ApiFailure && error.ambiguous) break;
          if (error instanceof ApiFailure && error.code === "creation_permit_required") return restartPairing(context, record);
          const transient = transientError(error);
          if (transient.code === "unavailable") return failed(context, record, "unavailable");
          save(context, withPhase(record, { attempt: null, name: "creating", permit: phase.permit }));
          throw transient;
        }
        break;
      }
      case "waiting": {
        if (!phase.reported) {
          record = save(context, withPhase(record, { ...phase, reported: true }));
          return waitingOutcome(record, phase.request, 3);
        }
        let state: RequestState | null = null;
        try {
          state = (await context.client.requestStatus({ locator: phase.request.locator, ownerToken: await ownerToken(phase.request) })).state;
        } catch (error) {
          if (error instanceof ApiFailure && error.code === "unavailable") return failed(context, record, "unavailable");
        }
        if (state === "submitted") {
          preflightSink(record);
          record = save(context, withPhase(record, { name: "picking", request: phase.request }));
          break;
        }
        if (state !== null && state !== "waiting") return failed(context, record, terminalError(state));
        if (!(await pause(context, statusDelay))) return waitingOutcome(record, phase.request, 4);
        statusDelay = Math.min(Math.round(statusDelay * 1.5), 15_000);
        break;
      }
      case "picking": {
        preflightSink(record);
        const token = await ownerToken(phase.request);
        try {
          const picked = await context.client.pickupRequest({ locator: phase.request.locator, ownerToken: token });
          record = save(context, withPhase(record, { name: "received", request: phase.request, response: encodeBase64Url(picked.bytes) }));
          break;
        } catch (error) {
          if (error instanceof ApiFailure && error.code === "rate_limited") throw new CliError("rate_limited");
        }
        let state: RequestState;
        try {
          state = (await context.client.requestStatus({ locator: phase.request.locator, ownerToken: token })).state;
        } catch (error) {
          if (error instanceof ApiFailure && error.code === "unavailable") return failed(context, record, "unavailable");
          throw transientError(error);
        }
        const recovery = pickupRecoveryForStatus(state);
        if (recovery === "lost") return failed(context, record, "pickup_lost");
        if (recovery === "terminal") return failed(context, record, terminalError(state));
        if (pickupRetried) throw new CliError("network");
        pickupRetried = true;
        break;
      }
      case "received": {
        const response = decodeBase64Url(phase.response);
        let values: ReadonlyMap<string, string>;
        try {
          values = await openAnswer(context, record, phase.request, response);
        } catch (error) {
          if (error instanceof KryptexCryptoError && error.code === "expired") return failed(context, record, "expired");
          return failed(context, record, "answer_invalid");
        }
        const delivered = await deliver(context, record, values);
        const receipt = await receiptDisplay(response);
        record = save(context, withPhase(record, { delivered, name: "delivered", receipt }));
        return deliveredOutcome(record, delivered, receipt);
      }
      case "delivered":
        return deliveredOutcome(record, phase.delivered, phase.receipt);
      case "failed":
        return errorOutcome(record.handle, phase.error);
    }
  }
}

/** Revokes the request on the service when this operation still holds its owner capability. */
export async function revokeRequest(context: Pick<FlowContext, "client">, record: RequestRecord): Promise<boolean> {
  const phase = record.phase;
  const request = phase.name === "waiting" || phase.name === "picking"
    ? phase.request
    : phase.name === "creating" ? phase.attempt : null;
  if (request === null) return false;
  try {
    await context.client.revokeRequest({ locator: request.locator, ownerToken: await ownerToken(request) });
    return true;
  } catch (error) {
    if (error instanceof ApiFailure && error.code === "unavailable") return false;
    throw transientError(error);
  }
}
