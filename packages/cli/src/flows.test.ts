import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApiFailure } from "@kryptex/client";
import type {
  CreatePermitStatusResponse,
  CreateResourceResponse,
  DeviceAccessRequest,
  DevicePairingRedeemRequest,
  DevicePairingRedeemResponse,
  DevicePairingStartRequest,
  DevicePairingStartResponse,
  DevicePermitRequest,
  DevicePermitResponse,
  DeviceStatusResponse,
  PairingRedeemRequest,
  PairingRedeemResponse,
  PairingStartRequest,
  PairingStartResponse,
  RequestCreateRequest,
  RequestOwnerRequest,
  RequestPickupMetadata,
  RequestState,
  RequestStatusResponse,
  RevokeResponse,
  SendCreateRequest,
  SendManageRequest,
  SendState,
  SendStatusResponse,
  StateCheckedMetadata
} from "@kryptex/contracts/api";
import type { RequestAnswer } from "@kryptex/contracts/payloads";
import {
  decodeBase64Url,
  decodeBundle,
  decodeRandomFactor,
  decryptRequestSchemaEnvelope,
  decryptSendEnvelope,
  deriveRandomFactor,
  deriveRequestWriteKeys,
  deriveSendRecipientKeys,
  encodeBase64Url,
  parseKxe1Header,
  randomBytes,
  sealRequestResponse
} from "@kryptex/crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { run, type CommandResult, type Runtime } from "./cli.js";
import type { NativeClient } from "./flow.js";

const START_SECONDS = 1_800_000_000;
const SECRET = "sk-live-0123456789abcdef";

interface StoredRequest {
  readonly envelope: Uint8Array;
  readonly ownerToken: string;
  readonly serverExpiresAt: number;
  response: Uint8Array | null;
  state: RequestState;
}

interface StoredSend {
  readonly envelope: Uint8Array;
  readonly manageToken: string;
  readonly serverExpiresAt: number;
  state: SendState;
}

type Fault = "commit-then-lose-response" | "lose-response" | null;

interface StoredGrant {
  readonly expiresAt: number;
  readonly mints: Map<string, { readonly mintedAt: number; readonly permit: string }>;
  minted: number;
  revoked: boolean;
  readonly token: string;
}

type StoredPairing =
  | { readonly kind: "device"; readonly deviceLocator: string; readonly deviceToken: string; readonly maxDays: number; readonly userCode: string }
  | { readonly kind: "legacy"; readonly pollToken: string; readonly userCode: string };

/** An in-memory service that follows the API contract closely enough to drive the CLI state machines. */
class FakeService implements NativeClient {
  clock = START_SECONDS * 1_000;
  approved = false;
  /** What the person picks on the confirmation page of a device pairing. */
  approvalScope: "device" | "transfer" = "transfer";
  /** False plays a service that predates device grants. */
  deviceRoutes = true;
  devicePairingsStarted = 0;
  mintFault: Fault = null;
  rejectNextPermitStatus = false;
  permitUsed = false;
  createFault: Fault = null;
  pickupFault: Fault = null;
  readonly grants = new Map<string, StoredGrant>();
  readonly requests = new Map<string, StoredRequest>();
  readonly sends = new Map<string, StoredSend>();
  readonly #mintedPermits = new Map<string, { readonly expiresAt: number; used: boolean }>();
  #permit = `v2.${encodeBase64Url(randomBytes(32))}`;
  #pairing: StoredPairing | null = null;

  get seconds(): number {
    return Math.floor(this.clock / 1_000);
  }

  #newPairing(pairing: StoredPairing): PairingStartResponse {
    this.#pairing = pairing;
    this.#permit = `v2.${encodeBase64Url(randomBytes(32))}`;
    this.approved = false;
    this.permitUsed = false;
    return { pairingExpiresAt: this.seconds + 600, serverTime: this.seconds, userCode: pairing.userCode };
  }

  startPairing(input: PairingStartRequest): Promise<PairingStartResponse> {
    return Promise.resolve(this.#newPairing({ kind: "legacy", pollToken: input.pollToken, userCode: "ABCD-EFGH" }));
  }

  redeemPairing(input: PairingRedeemRequest): Promise<PairingRedeemResponse> {
    if (this.#pairing?.kind !== "legacy" || this.#pairing.pollToken !== input.pollToken || this.#pairing.userCode !== input.userCode) {
      return Promise.reject(new ApiFailure("unavailable", false));
    }
    if (!this.approved) return Promise.resolve({ pairingExpiresAt: this.seconds + 600, state: "pending" });
    return Promise.resolve({ permit: this.#permit, permitExpiresAt: this.seconds + 600, serverTime: this.seconds, state: "approved" });
  }

  startDevicePairing(input: DevicePairingStartRequest): Promise<DevicePairingStartResponse> {
    if (!this.deviceRoutes) return Promise.reject(new ApiFailure("invalid_request", false));
    this.devicePairingsStarted += 1;
    return Promise.resolve(this.#newPairing({ ...input, kind: "device", userCode: "WXYZ-2345" }));
  }

  redeemDevicePairing(input: DevicePairingRedeemRequest): Promise<DevicePairingRedeemResponse> {
    const pairing = this.#pairing;
    if (pairing?.kind !== "device" || pairing.deviceToken !== input.deviceToken || pairing.userCode !== input.userCode) {
      return Promise.reject(new ApiFailure("unavailable", false));
    }
    if (!this.approved) return Promise.resolve({ pairingExpiresAt: this.seconds + 600, state: "pending" });
    if (this.approvalScope === "transfer") {
      return Promise.resolve({ permit: this.#permit, permitExpiresAt: this.seconds + 600, serverTime: this.seconds, state: "transfer" });
    }
    const grant = this.grants.get(pairing.deviceLocator) ?? { expiresAt: this.seconds + pairing.maxDays * 86400, mints: new Map(), minted: 0, revoked: false, token: pairing.deviceToken };
    this.grants.set(pairing.deviceLocator, grant);
    return Promise.resolve({ deviceExpiresAt: grant.expiresAt, state: "device" });
  }

  #grant(input: DeviceAccessRequest): StoredGrant {
    const grant = this.grants.get(input.deviceLocator);
    if (grant === undefined || !("deviceToken" in input) || grant.token !== input.deviceToken || this.seconds >= grant.expiresAt) {
      throw new ApiFailure("unavailable", false);
    }
    return grant;
  }

  mintDevicePermit(input: DevicePermitRequest): Promise<DevicePermitResponse> {
    const grant = this.#grant(input);
    if (grant.revoked) throw new ApiFailure("unavailable", false);
    const known = grant.mints.get(input.requestId);
    if (known !== undefined) {
      if (this.seconds - known.mintedAt > 120) throw new ApiFailure("unavailable", false);
      if (this.#mintedPermits.get(known.permit)?.used === true) throw new ApiFailure("creation_permit_required", false);
      return Promise.resolve({ permit: known.permit, permitExpiresAt: known.mintedAt + 120, serverTime: this.seconds });
    }
    if (grant.minted >= 50) throw new ApiFailure("quota_exhausted", false);
    const permit = `v3.${encodeBase64Url(randomBytes(32))}`;
    grant.mints.set(input.requestId, { mintedAt: this.seconds, permit });
    grant.minted += 1;
    this.#mintedPermits.set(permit, { expiresAt: this.seconds + 120, used: false });
    if (this.mintFault === "commit-then-lose-response") {
      this.mintFault = null;
      return Promise.reject(new ApiFailure("network", true));
    }
    return Promise.resolve({ permit, permitExpiresAt: this.seconds + 120, serverTime: this.seconds });
  }

  deviceStatus(input: DeviceAccessRequest): Promise<DeviceStatusResponse> {
    const grant = this.#grant(input);
    const hourlyMints = Array.from({ length: 24 }, (_, index) => index === 23 ? grant.minted : 0);
    return Promise.resolve({ expiresAt: grant.expiresAt, hourlyMints, quotaRemaining: 50 - grant.minted, state: grant.revoked ? "revoked" : "active" });
  }

  revokeDevice(input: DeviceAccessRequest): Promise<RevokeResponse> {
    this.#grant(input).revoked = true;
    return Promise.resolve({ state: "revoked" });
  }

  #permitUsable(permit: string | undefined): boolean {
    if (permit === this.#permit) return !this.permitUsed;
    const minted = permit === undefined ? undefined : this.#mintedPermits.get(permit);
    return minted !== undefined && !minted.used && this.seconds < minted.expiresAt;
  }

  permitStatus(permit?: string): Promise<CreatePermitStatusResponse> {
    if (this.rejectNextPermitStatus || !this.#permitUsable(permit)) {
      this.rejectNextPermitStatus = false;
      return Promise.reject(new ApiFailure("creation_permit_required", false));
    }
    return Promise.resolve({ permitExpiresAt: this.seconds + 120, serverTime: this.seconds, state: "unused" });
  }

  #consumePermit(permit: string | undefined): void {
    if (!this.#permitUsable(permit)) throw new ApiFailure("creation_permit_required", false);
    if (permit === this.#permit) {
      this.permitUsed = true;
      return;
    }
    const minted = permit === undefined ? undefined : this.#mintedPermits.get(permit);
    if (minted !== undefined) minted.used = true;
  }

  createRequest(input: RequestCreateRequest, permit?: string): Promise<CreateResourceResponse> {
    this.#consumePermit(permit);
    const serverExpiresAt = this.seconds + input.ttlSeconds;
    this.requests.set(input.locator, { envelope: decodeBase64Url(input.envelope), ownerToken: input.ownerToken, response: null, serverExpiresAt, state: "waiting" });
    if (this.createFault === "commit-then-lose-response") {
      this.createFault = null;
      return Promise.reject(new ApiFailure("network", true));
    }
    return Promise.resolve({ serverExpiresAt });
  }

  #request(input: RequestOwnerRequest): StoredRequest {
    const stored = this.requests.get(input.locator);
    if (stored?.ownerToken !== input.ownerToken) throw new ApiFailure("unavailable", false, this.seconds);
    return stored;
  }

  requestStatus(input: RequestOwnerRequest): Promise<RequestStatusResponse & StateCheckedMetadata> {
    const stored = this.#request(input);
    return Promise.resolve({ serverExpiresAt: stored.serverExpiresAt, state: stored.state, stateCheckedAt: this.seconds });
  }

  pickupRequest(input: RequestOwnerRequest): Promise<{ readonly bytes: Uint8Array<ArrayBuffer>; readonly metadata: RequestPickupMetadata }> {
    const stored = this.#request(input);
    if (stored.state !== "submitted" || stored.response === null) throw new ApiFailure("unavailable", false);
    stored.state = "picked_up";
    if (this.pickupFault === "lose-response") return Promise.reject(new ApiFailure("network", true));
    return Promise.resolve({ bytes: new Uint8Array(stored.response), metadata: { receipt: "r", serverExpiresAt: stored.serverExpiresAt } });
  }

  revokeRequest(input: RequestOwnerRequest): Promise<RevokeResponse> {
    this.#request(input).state = "revoked";
    return Promise.resolve({ state: "revoked" });
  }

  createSend(input: SendCreateRequest, permit?: string): Promise<CreateResourceResponse> {
    this.#consumePermit(permit);
    const serverExpiresAt = this.seconds + input.ttlSeconds;
    this.sends.set(input.locator, { envelope: decodeBase64Url(input.envelope), manageToken: input.manageToken, serverExpiresAt, state: "active" });
    return Promise.resolve({ serverExpiresAt });
  }

  #send(input: SendManageRequest): StoredSend {
    const stored = this.sends.get(input.locator);
    if (stored?.manageToken !== input.manageToken) throw new ApiFailure("unavailable", false, this.seconds);
    return stored;
  }

  sendStatus(input: SendManageRequest): Promise<SendStatusResponse & StateCheckedMetadata> {
    const stored = this.#send(input);
    return Promise.resolve({ failedAccessAttempts: 0, releasedAt: [], remainingRetrievals: 1, serverExpiresAt: stored.serverExpiresAt, state: stored.state, stateCheckedAt: this.seconds });
  }

  revokeSend(input: SendManageRequest): Promise<RevokeResponse> {
    this.#send(input).state = "revoked";
    return Promise.resolve({ state: "revoked" });
  }

  /** Plays the person who opens the write link: decrypts the form and seals an answer to the owner key. */
  async submit(writeUrl: string, answer: (fieldId: string) => string): Promise<void> {
    const bundle = decodeBundle(writeUrl.slice(writeUrl.indexOf("#") + 1));
    if (bundle.kind !== 3) throw new Error("not a write link");
    const stored = this.requests.get(encodeBase64Url(bundle.requestLocator));
    if (stored === undefined) throw new Error("unknown request");
    const keys = await deriveRequestWriteKeys(bundle.writeSeed, 0);
    const schema = await decryptRequestSchemaEnvelope(stored.envelope, keys.schemaKey, 0, bundle.recipientPublicKey, stored.serverExpiresAt, this.seconds);
    const answers: RequestAnswer[] = schema.payload.fields.filter((entry) => entry.type !== "instruction").map((entry) => ({ id: entry.id, value: answer(entry.id) }));
    stored.response = await sealRequestResponse({
      expectedClientNotAfter: schema.header.clientNotAfter,
      payload: { answers, kind: "request-response", schema: schema.payload },
      recipientPublicKey: bundle.recipientPublicKey,
      requestLocator: bundle.requestLocator,
      schemaDigest: schema.header.schemaDigest
    });
    stored.state = "submitted";
  }
}

let project: string;
let state: string;
let service: FakeService;
let stderr: Buffer[];
let printed: string[];

beforeEach(() => {
  project = realpathSync(mkdtempSync(join(tmpdir(), "kryptex-flow-")));
  state = join(project, ".state");
  execFileSync("git", ["init", "-q"], { cwd: project });
  writeFileSync(join(project, ".gitignore"), ".env\n.state/\nhandoff.txt\n");
  writeFileSync(join(project, "form.json"), JSON.stringify({
    fields: [
      { help: "", label: "Read me", required: false, type: "instruction" },
      { help: "Starts with sk-", label: "API key", required: true, target: "API_KEY", type: "secret" },
      { help: "", label: "Region", required: false, target: "REGION", type: "text" }
    ],
    title: "Deploy credentials"
  }));
  service = new FakeService();
  stderr = [];
  printed = [];
});

afterEach(() => {
  rmSync(project, { force: true, recursive: true });
});

function runtime(): Runtime {
  return {
    clientFor: () => service,
    cwd: project,
    environment: { KRYPTEX_ORIGIN: "https://kryptex.example", KRYPTEX_STATE_DIR: state },
    now: () => service.clock,
    sleep: (milliseconds) => {
      service.clock += milliseconds;
      return Promise.resolve();
    },
    stderr: (chunk) => {
      stderr.push(chunk);
    }
  };
}

async function kryptex(...argv: string[]): Promise<{ readonly exitCode: number; readonly output: Readonly<Record<string, unknown>> }> {
  const result: CommandResult = await run(argv, runtime());
  if ("text" in result) throw new Error("unexpected text output");
  printed.push(JSON.stringify(result.output));
  return result;
}

function text(output: Readonly<Record<string, unknown>>, key: string): string {
  const value = output[key];
  if (typeof value !== "string") throw new Error(`missing ${key}`);
  return value;
}

async function createRequest(...sink: string[]): Promise<string> {
  const created = await kryptex("request", "create", "--spec", "form.json", ...sink);
  expect(created.exitCode).toBe(3);
  expect(created.output).toMatchObject({ action: "pair", pairUrl: "https://kryptex.example/pair/device", state: "pairing", userCode: "WXYZ-2345" });
  return text(created.output, "handle");
}

async function pairAndCreate(handle: string): Promise<string> {
  service.approved = true;
  const created = await kryptex("wait", handle);
  expect(created).toMatchObject({ exitCode: 3, output: { action: "hand_over_write_link", handle, state: "waiting" } });
  return text(created.output, "writeUrl");
}

function answers(fieldId: string): string {
  return fieldId === "field002" ? SECRET : "";
}

describe("request", () => {
  it("delivers an answer into an ignored dotenv file without printing it", async () => {
    writeFileSync(join(project, ".env"), "# kept\nREGION=eu\n");
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "literal");
    expect((await kryptex("wait", handle, "--timeout", "5")).output).toMatchObject({ action: "pair", state: "pairing" });
    const writeUrl = await pairAndCreate(handle);
    expect(writeUrl).toMatch(/^https:\/\/kryptex\.example\/r#/u);
    expect(await kryptex("wait", handle, "--timeout", "5")).toMatchObject({ exitCode: 4, output: { state: "waiting", writeUrl } });

    await service.submit(writeUrl, answers);
    const delivered = await kryptex("wait", handle);
    expect(delivered).toMatchObject({ exitCode: 0, output: { delivered: { keys: ["API_KEY"], path: ".env" }, state: "delivered" } });
    expect(readFileSync(join(project, ".env"), "utf8")).toBe(`# kept\nREGION=eu\nAPI_KEY='${SECRET}'\n`);
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 0, output: { state: "delivered" } });

    expect(printed.join("\n")).not.toContain(SECRET);
    expect(readFileSync(join(state, `${handle}.json`), "utf8")).not.toContain(SECRET);
  });

  it("runs the recorded command with the values and redacts its output", async () => {
    const handle = await createRequest("--exec", "--", "sh", "-c", "echo \"key=$API_KEY region=[$REGION]\"");
    await service.submit(await pairAndCreate(handle), answers);
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 0, output: { delivered: { command: "sh", exitCode: 0, keys: ["API_KEY", "REGION"] } } });
    expect(Buffer.concat(stderr).toString("utf8")).toBe("key=[redacted:API_KEY] region=[]\n");
    expect(printed.join("\n")).not.toContain(SECRET);
  });

  it("keeps the answer and retries the command after a failed run", async () => {
    const marker = join(project, "marker");
    const handle = await createRequest("--exec", "--", "sh", "-c", `test -f '${marker}'`);
    await service.submit(await pairAndCreate(handle), answers);
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 1, output: { error: "exec_failed", retryable: true } });
    writeFileSync(marker, "");
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 0, output: { state: "delivered" } });
  });

  it("reconciles a create whose response was lost after the service committed it", async () => {
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "expand");
    service.createFault = "commit-then-lose-response";
    const writeUrl = await pairAndCreate(handle);
    expect(service.requests.size).toBe(1);
    await service.submit(writeUrl, answers);
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 0 });
  });

  it("reports pickup_lost when the service released the answer but the response never arrived", async () => {
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "literal");
    await service.submit(await pairAndCreate(handle), answers);
    service.pickupFault = "lose-response";
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 1, output: { error: "pickup_lost", retryable: false } });
    expect(existsSync(join(project, ".env"))).toBe(false);
  });

  it("refuses to pick up while the dotenv file would conflict", async () => {
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "literal");
    await service.submit(await pairAndCreate(handle), answers);
    writeFileSync(join(project, ".env"), "API_KEY=a\nAPI_KEY=b\n");
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 1, output: { error: "env_file_conflict" } });
    expect([...service.requests.values()][0]?.state).toBe("submitted");
    writeFileSync(join(project, ".env"), "API_KEY=a\n");
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 0 });
    expect(readFileSync(join(project, ".env"), "utf8")).toBe(`API_KEY='${SECRET}'\n`);
  });

  it("rejects an answer sealed for a different form", async () => {
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "literal");
    const writeUrl = await pairAndCreate(handle);
    const stored = [...service.requests.values()][0];
    if (stored === undefined) throw new Error("no request");
    const other = await createOtherForm();
    await service.submit(other, () => SECRET);
    stored.response = [...service.requests.values()][1]?.response ?? null;
    stored.state = "submitted";
    expect(writeUrl).not.toBe(other);
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 1, output: { error: "answer_invalid" } });
  });

  it("starts a new pairing when the permit was already used", async () => {
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "literal");
    service.approved = true;
    service.permitUsed = true;
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 3, output: { action: "pair", state: "pairing" } });
  });

  it("revokes and forgets a waiting request on discard", async () => {
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "literal");
    await pairAndCreate(handle);
    expect(await kryptex("discard", handle)).toMatchObject({ exitCode: 0, output: { discarded: true, handle, revoked: true } });
    expect([...service.requests.values()][0]?.state).toBe("revoked");
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 1, output: { error: "state_invalid" } });
  });

  it("lists operations without capabilities", async () => {
    const handle = await createRequest("--env-file", ".env", "--env-dialect", "literal");
    const writeUrl = await pairAndCreate(handle);
    const listed = await kryptex("list");
    expect(listed.output).toEqual({ operations: [{ expiresAt: START_SECONDS + 604800, handle, kind: "request", origin: "https://kryptex.example", state: "waiting", target: ".env" }] });
    expect(JSON.stringify(listed.output)).not.toContain(writeUrl.slice(writeUrl.indexOf("#") + 1));
  });
});

/** Creates a second, unrelated request and returns its write link. */
async function createOtherForm(): Promise<string> {
  writeFileSync(join(project, "other.json"), JSON.stringify({ fields: [{ help: "", label: "Other", required: true, target: "API_KEY", type: "secret" }], title: "Other" }));
  service.permitUsed = false;
  const created = await kryptex("request", "create", "--spec", "other.json", "--env-file", ".env", "--env-dialect", "literal");
  const handle = text(created.output, "handle");
  service.approved = true;
  return text((await kryptex("wait", handle)).output, "writeUrl");
}

describe("send", () => {
  it("creates a send whose second key exists only in the hand-off file", async () => {
    writeFileSync(join(project, ".env"), `API_KEY=${SECRET}\nREGION=eu\n`);
    const created = await kryptex("send", "create", "--from-env-file", ".env", "--env-dialect", "literal", "--key", "API_KEY", "--key", "REGION", "--handoff-file", "handoff.txt");
    expect(created).toMatchObject({ exitCode: 3, output: { action: "pair", kind: "send" } });
    const handle = text(created.output, "handle");
    service.approved = true;

    const handed = await kryptex("wait", handle);
    expect(handed).toMatchObject({ exitCode: 3, output: { action: "hand_over_recipient_link", handle, handoffFile: "handoff.txt", state: "created" } });
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 0, output: { state: "created" } });

    const handoff = readFileSync(join(project, "handoff.txt"), "utf8");
    const secondKey = /^Second key: (.+)$/mu.exec(handoff)?.[1] ?? "";
    expect(handoff).toMatch(/^Management link: https:\/\/kryptex\.example\/m#/mu);
    for (const output of printed) {
      expect(output).not.toContain(SECRET);
      expect(output).not.toContain(secondKey);
    }

    const recipientUrl = text(handed.output, "recipientUrl");
    const bundle = decodeBundle(recipientUrl.slice(recipientUrl.indexOf("#") + 1));
    if (bundle.kind !== 1) throw new Error("not a recipient link");
    expect(bundle.factorMode).toBe(2);
    const keys = await deriveSendRecipientKeys(bundle.sendSeed, 2, await deriveRandomFactor(decodeRandomFactor(secondKey)));
    const stored = service.sends.get(encodeBase64Url(keys.locator));
    if (stored === undefined) throw new Error("send not stored under the recipient locator");
    expect(parseKxe1Header(stored.envelope).maxRetrievals).toBe(1);
    const opened = await decryptSendEnvelope(stored.envelope, keys.contentKey, 2, stored.serverExpiresAt, service.seconds);
    expect(opened.payload).toEqual({ fields: [{ label: "API_KEY", type: "secret", value: SECRET }, { label: "REGION", type: "secret", value: "eu" }], kind: "fields" });
  });

  it("refuses a hand-off file that already exists or Git would track", async () => {
    writeFileSync(join(project, ".env"), `API_KEY=${SECRET}\n`);
    writeFileSync(join(project, "handoff.txt"), "");
    const exists = await kryptex("send", "create", "--from-env-file", ".env", "--env-dialect", "literal", "--key", "API_KEY", "--handoff-file", "handoff.txt");
    expect(exists).toMatchObject({ exitCode: 1, output: { error: "target_invalid" } });
    const visible = await kryptex("send", "create", "--from-env-file", ".env", "--env-dialect", "literal", "--key", "API_KEY", "--handoff-file", "visible.txt");
    expect(visible).toMatchObject({ exitCode: 1, output: { error: "target_invalid" } });
    expect(existsSync(state)).toBe(false);
  });
});

const ORIGIN = "https://kryptex.example";
const ENV_SINK = ["--env-file", ".env", "--env-dialect", "literal"];

function devicePath(): string {
  return join(state, "devices", `${createHash("sha256").update(ORIGIN).digest("hex")}.json`);
}

function onlyGrant(): StoredGrant & { readonly locator: string } {
  const entries = [...service.grants];
  const [entry] = entries;
  if (entries.length !== 1 || entry === undefined) throw new Error("expected exactly one grant");
  return Object.assign(entry[1], { locator: entry[0] });
}

/** Replaces the device file with mutated content, keeping mode 0600. */
function rewriteDeviceFile(change: (grant: Record<string, unknown>) => Record<string, unknown>): void {
  const parsed: unknown = JSON.parse(readFileSync(devicePath(), "utf8"));
  if (typeof parsed !== "object" || parsed === null) throw new Error("device file is not an object");
  writeFileSync(devicePath(), JSON.stringify(change({ ...parsed })), { mode: 0o600 });
}

/** Runs the first operation through a device pairing that the person approves for this machine. */
async function pairDevice(...extra: string[]): Promise<string> {
  const handle = await createRequest(...ENV_SINK, ...extra);
  service.approvalScope = "device";
  await pairAndCreate(handle);
  return handle;
}

async function stateOf(handle: string): Promise<unknown> {
  const listed = await kryptex("list");
  const operations = listed.output["operations"];
  if (!Array.isArray(operations)) throw new Error("no operations");
  const found: unknown = operations.find((entry: unknown) => typeof entry === "object" && entry !== null && Reflect.get(entry, "handle") === handle);
  return typeof found === "object" && found !== null ? Reflect.get(found, "state") : undefined;
}

function expectNoDeviceSecrets(): void {
  const grant = onlyGrant();
  for (const output of printed) {
    expect(output).not.toContain(grant.token);
    expect(output).not.toContain(grant.locator);
  }
}

describe("device grants", () => {
  it("pairs once and then creates requests and sends without pairing", async () => {
    await pairDevice("--device-days", "7");
    const grant = onlyGrant();
    expect(grant.expiresAt).toBe(START_SECONDS + 7 * 86400);
    expect(statSync(join(state, "devices")).mode & 0o777).toBe(0o700);
    expect(statSync(devicePath()).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(devicePath(), "utf8"))).toEqual({
      deviceExpiresAt: grant.expiresAt,
      deviceLocator: grant.locator,
      deviceToken: grant.token,
      origin: ORIGIN,
      version: 1
    });

    const second = await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK);
    expect(second).toMatchObject({ exitCode: 3, output: { action: "hand_over_write_link", kind: "request", state: "waiting" } });
    await service.submit(text(second.output, "writeUrl"), answers);
    expect(await kryptex("wait", text(second.output, "handle"))).toMatchObject({ exitCode: 0, output: { state: "delivered" } });

    writeFileSync(join(project, "source.env"), `API_KEY=${SECRET}\n`);
    writeFileSync(join(project, ".gitignore"), ".env\n.state/\nhandoff.txt\nsource.env\n");
    const sent = await kryptex("send", "create", "--from-env-file", "source.env", "--env-dialect", "literal", "--key", "API_KEY", "--handoff-file", "handoff.txt");
    expect(sent).toMatchObject({ exitCode: 3, output: { action: "hand_over_recipient_link", kind: "send", state: "created" } });

    expect(service.devicePairingsStarted).toBe(1);
    expect(grant.minted).toBe(3);
    expectNoDeviceSecrets();
  });

  it("asks for the requested device lifetime and rejects others", async () => {
    expect(await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK, "--device-days", "14")).toMatchObject({ exitCode: 2, output: { error: "usage" } });
    expect(existsSync(state)).toBe(false);
  });

  it("pairs again after a transfer-only approval", async () => {
    await pairAndCreate(await createRequest(...ENV_SINK));
    expect(existsSync(devicePath())).toBe(false);
    expect(service.grants.size).toBe(0);
    await createRequest(...ENV_SINK);
    expect(service.devicePairingsStarted).toBe(2);
  });

  it("replays a mint whose response was lost with the same request ID", async () => {
    await pairDevice();
    service.mintFault = "commit-then-lose-response";
    const lost = await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK);
    expect(lost).toMatchObject({ exitCode: 1, output: { error: "network", retryable: true } });
    const handle = text(lost.output, "handle");
    expect(await stateOf(handle)).toBe("minting");
    expect(onlyGrant().minted).toBe(2);

    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 3, output: { action: "hand_over_write_link", handle } });
    expect(onlyGrant().minted).toBe(2);
  });

  it("mints with a fresh request ID once the service no longer repeats the lost mint", async () => {
    await pairDevice();
    service.mintFault = "commit-then-lose-response";
    const handle = text((await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK)).output, "handle");
    service.clock += 125_000;
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 3, output: { action: "hand_over_write_link", handle } });
    expect(onlyGrant().minted).toBe(3);
    expect(existsSync(devicePath())).toBe(true);
  });

  it("keeps the operation and the device file when the quota is exhausted", async () => {
    await pairDevice();
    onlyGrant().minted = 50;
    const exhausted = await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK);
    expect(exhausted).toMatchObject({ exitCode: 1, output: { error: "quota_exhausted", retryable: true } });
    const handle = text(exhausted.output, "handle");
    expect(await stateOf(handle)).toBe("minting");
    expect(existsSync(devicePath())).toBe(true);

    onlyGrant().minted = 0;
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 3, output: { action: "hand_over_write_link", handle } });
  });

  it("deletes the device file of a revoked grant and pairs again", async () => {
    await pairDevice();
    onlyGrant().revoked = true;
    const created = await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK);
    expect(created).toMatchObject({ exitCode: 3, output: { action: "pair", pairUrl: `${ORIGIN}/pair/device`, state: "pairing" } });
    expect(existsSync(devicePath())).toBe(false);
    expect(service.devicePairingsStarted).toBe(2);
  });

  it("mints again when the service rejects a minted permit", async () => {
    await pairDevice();
    service.rejectNextPermitStatus = true;
    expect(await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK)).toMatchObject({ exitCode: 3, output: { action: "hand_over_write_link" } });
    expect(onlyGrant().minted).toBe(3);
  });

  it("falls back to a one-permit pairing on a service without device grants", async () => {
    service.deviceRoutes = false;
    const created = await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK);
    expect(created).toMatchObject({ exitCode: 3, output: { action: "pair", pairUrl: `${ORIGIN}/pair#ABCD-EFGH`, state: "pairing", userCode: "ABCD-EFGH" } });
    await pairAndCreate(text(created.output, "handle"));
    expect(existsSync(devicePath())).toBe(false);
  });

  it("finishes a pairing record written by an earlier CLI through the legacy pairing", async () => {
    service.deviceRoutes = false;
    const handle = text((await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK)).output, "handle");
    const path = join(state, `${handle}.json`);
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof parsed !== "object" || parsed === null) throw new Error("record is not an object");
    expect(Object.keys(parsed)).toContain("deviceDays");
    const earlier = Object.fromEntries(Object.entries(parsed).filter(([key]) => key !== "deviceDays"));
    writeFileSync(path, JSON.stringify(earlier), { mode: 0o600 });
    service.deviceRoutes = true;

    expect(await kryptex("wait", handle, "--timeout", "5")).toMatchObject({ exitCode: 4, output: { action: "pair", pairUrl: `${ORIGIN}/pair#ABCD-EFGH` } });
    await pairAndCreate(handle);
  });

  it("replaces an expired legacy pairing with a device pairing", async () => {
    service.deviceRoutes = false;
    const handle = text((await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK)).output, "handle");
    service.deviceRoutes = true;
    service.clock += 601_000;
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 3, output: { action: "pair", pairUrl: `${ORIGIN}/pair/device`, userCode: "WXYZ-2345" } });
  });

  it.each([
    ["readable by others", () => {
      chmodSync(devicePath(), 0o644);
    }],
    ["an extra key", () => {
      rewriteDeviceFile((grant) => ({ ...grant, scope: "device" }));
    }],
    ["another origin", () => {
      rewriteDeviceFile((grant) => ({ ...grant, origin: "https://other.example" }));
    }],
    ["another version", () => {
      rewriteDeviceFile((grant) => ({ ...grant, version: 2 }));
    }],
    ["a short token", () => {
      rewriteDeviceFile((grant) => ({ ...grant, deviceToken: "AAAA" }));
    }]
  ])("blocks the origin while the device file is %s, until device forget --force", async (_name, corrupt) => {
    await pairDevice();
    corrupt();
    const handles = (await kryptex("list")).output["operations"];
    expect(await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK)).toMatchObject({ exitCode: 1, output: { error: "state_invalid" } });
    expect((await kryptex("list")).output["operations"]).toEqual(handles);
    expect(await kryptex("device", "status")).toEqual({ exitCode: 0, output: { device: { state: "invalid" }, origin: ORIGIN } });
    expect(await kryptex("device", "forget")).toMatchObject({ exitCode: 1, output: { error: "state_invalid" } });
    expect(existsSync(devicePath())).toBe(true);

    expect(await kryptex("device", "forget", "--force")).toEqual({ exitCode: 0, output: { forgotten: true, origin: ORIGIN, revoked: false } });
    expect(existsSync(devicePath())).toBe(false);
    await createRequest(...ENV_SINK);
  });

  it("treats a device file past its expiry as absent", async () => {
    await pairDevice();
    rewriteDeviceFile((grant) => ({ ...grant, deviceExpiresAt: service.seconds }));
    expect(await kryptex("device", "status")).toEqual({ exitCode: 0, output: { device: { state: "none" }, origin: ORIGIN } });
    await createRequest(...ENV_SINK);
  });

  it("fails a minting operation while the device file is invalid and keeps its state", async () => {
    await pairDevice();
    onlyGrant().minted = 50;
    const handle = text((await kryptex("request", "create", "--spec", "form.json", ...ENV_SINK)).output, "handle");
    chmodSync(devicePath(), 0o640);
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 1, output: { error: "state_invalid", handle } });
    expect(await stateOf(handle)).toBe("minting");
    await kryptex("device", "forget", "--force");
    expect(await kryptex("wait", handle)).toMatchObject({ exitCode: 3, output: { action: "pair", handle } });
  });

  it("reports and revokes the grant without printing the device token", async () => {
    expect(await kryptex("device", "status")).toEqual({ exitCode: 0, output: { device: { state: "none" }, origin: ORIGIN } });
    await pairDevice();
    const grant = onlyGrant();
    expect(await kryptex("device", "status", "--origin", ORIGIN)).toEqual({
      exitCode: 0,
      output: {
        device: { expiresAt: grant.expiresAt, hourlyMints: [...Array.from({ length: 23 }, () => 0), 1], quotaRemaining: 49, state: "active" },
        origin: ORIGIN
      }
    });
    expect(await kryptex("device", "forget")).toEqual({ exitCode: 0, output: { forgotten: true, origin: ORIGIN, revoked: true } });
    expect(grant.revoked).toBe(true);
    expect(existsSync(devicePath())).toBe(false);
    expect(await kryptex("device", "status")).toEqual({ exitCode: 0, output: { device: { state: "none" }, origin: ORIGIN } });
    expect(await kryptex("device", "forget")).toEqual({ exitCode: 0, output: { forgotten: false, origin: ORIGIN, revoked: false } });
    expectNoDeviceSecrets();
  });

  it("keeps the device file when the revoke fails, unless forced", async () => {
    await pairDevice();
    const revokeDevice = service.revokeDevice.bind(service);
    service.revokeDevice = () => Promise.reject(new ApiFailure("network", true));
    expect(await kryptex("device", "forget")).toMatchObject({ exitCode: 1, output: { error: "network", retryable: true } });
    expect(existsSync(devicePath())).toBe(true);
    expect(await kryptex("device", "forget", "--force")).toEqual({ exitCode: 0, output: { forgotten: true, origin: ORIGIN, revoked: false } });
    service.revokeDevice = revokeDevice;
    expect(existsSync(devicePath())).toBe(false);
  });
});
