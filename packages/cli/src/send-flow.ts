import { ApiFailure, reconcileSendCreation } from "@kryptex/client";
import type { SendPayload } from "@kryptex/contracts/payloads";
import {
  decodeBase64Url,
  deriveRandomFactor,
  deriveSendKeys,
  deriveSendManagementKeys,
  encodeBase64Url,
  encodeBundle,
  encodeRandomFactor,
  encryptSendEnvelope,
  randomBytes
} from "@kryptex/crypto";
import { readDotenvKeys } from "./dotenv.js";
import { CliError, type ErrorCode } from "./errors.js";
import {
  boundedSleep,
  DeadlineReached,
  errorOutcome,
  pairingOutcome,
  pollPairing,
  save,
  startPairing,
  stillWaitingOutcome,
  transientError,
  type FlowContext,
  type Outcome
} from "./flow.js";
import { checkProjectPath, createProjectFile, readProjectFile } from "./project.js";
import type { CreatedSend, SendAttempt, SendPhase, SendRecord } from "./record.js";

function withPhase(record: SendRecord, phase: SendPhase): SendRecord {
  return { ...record, phase };
}

function failed(context: FlowContext, record: SendRecord, error: ErrorCode): Outcome {
  save(context, withPhase(record, { error, name: "failed" }));
  return errorOutcome(record.handle, error);
}

async function restartPairing(context: FlowContext, record: SendRecord): Promise<Outcome> {
  const pairing = await startPairing(context.client);
  const next = save(context, withPhase(record, { name: "pairing", pairing }));
  return pairingOutcome(next, pairing, 3);
}

async function manageToken(send: Pick<CreatedSend, "manageSeed">): Promise<string> {
  return encodeBase64Url((await deriveSendManagementKeys(decodeBase64Url(send.manageSeed))).manageToken);
}

/** Reads the source values now, so they exist afterwards only inside the envelope. */
export function readSource(record: SendRecord): ReadonlyMap<string, string> {
  const absolute = checkProjectPath(record.projectRoot, record.source.path, { existence: "required", output: false });
  const content = readProjectFile(absolute);
  if (content === null) throw new CliError("source_invalid");
  return readDotenvKeys(content, record.source.dialect, record.source.keys);
}

async function buildAttempt(record: SendRecord, serverTime: number): Promise<{ readonly attempt: SendAttempt; readonly retrieveToken: string; readonly manageToken: string }> {
  const values = readSource(record);
  const payload: SendPayload = {
    fields: [...values].map(([label, value]) => ({ label, type: "secret", value })),
    kind: "fields"
  };
  const secondKey = randomBytes(16);
  const sendSeed = randomBytes(32);
  const manageSeed = randomBytes(32);
  const keys = await deriveSendKeys(sendSeed, manageSeed, 2, await deriveRandomFactor(secondKey));
  const clientNotAfter = serverTime + record.ttl;
  let envelope: Uint8Array;
  try {
    envelope = await encryptSendEnvelope({ clientNotAfter, contentKey: keys.contentKey, factorMode: 2, maxRetrievals: record.maxRetrievals, payload });
  } catch {
    throw new CliError("source_invalid");
  }
  return {
    attempt: {
      attemptId: encodeBase64Url(randomBytes(16)),
      clientNotAfter,
      envelope: encodeBase64Url(envelope),
      locator: encodeBase64Url(keys.locator),
      manageSeed: encodeBase64Url(manageSeed),
      secondKey: encodeBase64Url(secondKey),
      sendSeed: encodeBase64Url(sendSeed),
      settleNotAfter: serverTime + 60
    },
    manageToken: encodeBase64Url(keys.manageToken),
    retrieveToken: encodeBase64Url(keys.retrieveToken)
  };
}

function createdFromAttempt(attempt: SendAttempt, serverExpiresAt: number): CreatedSend {
  return {
    locator: attempt.locator,
    manageSeed: attempt.manageSeed,
    secondKey: attempt.secondKey,
    sendSeed: attempt.sendSeed,
    serverExpiresAt
  };
}

export function recipientUrl(origin: string, send: CreatedSend): string {
  const bundle = encodeBundle({
    factorMode: 2,
    kind: 1,
    salt: new Uint8Array(16),
    sendSeed: decodeBase64Url(send.sendSeed),
    serverExpiresAt: send.serverExpiresAt
  });
  return `${origin}/s#${bundle}`;
}

export function managementUrl(origin: string, send: CreatedSend): string {
  const bundle = encodeBundle({
    kind: 2,
    locator: decodeBase64Url(send.locator),
    manageSeed: decodeBase64Url(send.manageSeed),
    serverExpiresAt: send.serverExpiresAt
  });
  return `${origin}/m#${bundle}`;
}

/** The whole file is derived from the stored send, so a retry after a crash can recognize its own earlier write. */
export function handoffContent(origin: string, send: CreatedSend): string {
  return [
    "Kryptex hand-off",
    "",
    `Second key: ${encodeRandomFactor(decodeBase64Url(send.secondKey))}`,
    "Send the second key to the recipient through a different channel than the recipient link: a call, a chat on another device, or in person. Never append it to the link.",
    "",
    `Management link: ${managementUrl(origin, send)}`,
    "Keep the management link for yourself. It lets you check releases, shorten the expiry, or revoke the secret.",
    "",
    `Expires: ${new Date(send.serverExpiresAt * 1_000).toISOString()}`,
    ""
  ].join("\n");
}

function writeHandoff(record: SendRecord, send: CreatedSend): void {
  const absolute = checkProjectPath(record.projectRoot, record.handoffPath, { existence: "either", output: true });
  const content = handoffContent(record.origin, send);
  const existing = readProjectFile(absolute);
  if (existing !== null) {
    if (existing !== content) throw new CliError("handoff_failed");
    return;
  }
  try {
    createProjectFile(absolute, content);
  } catch {
    throw new CliError("handoff_failed");
  }
}

function createdOutcome(record: SendRecord, url: string, serverExpiresAt: number, exitCode: 0 | 3): Outcome {
  const output = {
    expiresAt: serverExpiresAt,
    handle: record.handle,
    handoffFile: record.handoffPath,
    kind: record.kind,
    recipientUrl: url,
    state: "created"
  };
  return { exitCode, output: exitCode === 3 ? { action: "hand_over_recipient_link", ...output } : output };
}

/** Advances a send until a person must act, it finishes, or the deadline passes. See "Send lifecycle" in docs/spec/cli-v1.md. */
export async function advanceSend(context: FlowContext, initial: SendRecord): Promise<Outcome> {
  let record = initial;
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
          let reconciled: Awaited<ReturnType<typeof reconcileSendCreation>>;
          try {
            reconciled = await reconcileSendCreation(context.client, attempt.locator, await manageToken(attempt), attempt.settleNotAfter, boundedSleep(context));
          } catch (error) {
            if (error instanceof DeadlineReached) return stillWaitingOutcome(record, "creating");
            throw error;
          }
          record = save(context, withPhase(record, reconciled.kind === "created"
            ? { name: "handoff", send: createdFromAttempt(attempt, reconciled.serverExpiresAt) }
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
        const built = await buildAttempt(record, serverTime);
        const attempt = built.attempt;
        record = save(context, withPhase(record, { attempt, name: "creating", permit: phase.permit }));
        try {
          const created = await context.client.createSend({
            attemptId: attempt.attemptId,
            clientNotAfter: attempt.clientNotAfter,
            envelope: attempt.envelope,
            locator: attempt.locator,
            manageToken: built.manageToken,
            maxRetrievals: record.maxRetrievals,
            retrieveToken: built.retrieveToken,
            settleNotAfter: attempt.settleNotAfter,
            ttlSeconds: record.ttl
          }, phase.permit);
          record = save(context, withPhase(record, { name: "handoff", send: createdFromAttempt(attempt, created.serverExpiresAt) }));
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
      case "handoff": {
        writeHandoff(record, phase.send);
        record = save(context, withPhase(record, {
          name: "created",
          recipientUrl: recipientUrl(record.origin, phase.send),
          reported: false,
          serverExpiresAt: phase.send.serverExpiresAt
        }));
        break;
      }
      case "created": {
        if (phase.reported) return createdOutcome(record, phase.recipientUrl, phase.serverExpiresAt, 0);
        record = save(context, withPhase(record, { ...phase, reported: true }));
        return createdOutcome(record, phase.recipientUrl, phase.serverExpiresAt, 3);
      }
      case "failed":
        return errorOutcome(record.handle, phase.error);
    }
  }
}

/** Revokes the send while this operation still holds its management capability; after the hand-off only the person holds it. */
export async function revokeSend(context: Pick<FlowContext, "client">, record: SendRecord): Promise<boolean> {
  const phase = record.phase;
  const send = phase.name === "handoff" ? phase.send : phase.name === "creating" ? phase.attempt : null;
  if (send === null) return false;
  try {
    await context.client.revokeSend({ locator: send.locator, manageToken: await manageToken(send) });
    return true;
  } catch (error) {
    if (error instanceof ApiFailure && error.code === "unavailable") return false;
    throw transientError(error);
  }
}
