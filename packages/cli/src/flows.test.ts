import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApiFailure } from "@kryptex/client";
import type {
  CreatePermitStatusResponse,
  CreateResourceResponse,
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

/** An in-memory service that follows the API contract closely enough to drive the CLI state machines. */
class FakeService implements NativeClient {
  clock = START_SECONDS * 1_000;
  approved = false;
  permitUsed = false;
  createFault: Fault = null;
  pickupFault: Fault = null;
  readonly requests = new Map<string, StoredRequest>();
  readonly sends = new Map<string, StoredSend>();
  readonly #permit = `v2.${encodeBase64Url(randomBytes(32))}`;
  #pairing: { readonly pollToken: string; readonly userCode: string } | null = null;

  get seconds(): number {
    return Math.floor(this.clock / 1_000);
  }

  startPairing(input: PairingStartRequest): Promise<PairingStartResponse> {
    this.#pairing = { pollToken: input.pollToken, userCode: "ABCD-EFGH" };
    this.approved = false;
    return Promise.resolve({ pairingExpiresAt: this.seconds + 600, serverTime: this.seconds, userCode: "ABCD-EFGH" });
  }

  redeemPairing(input: PairingRedeemRequest): Promise<PairingRedeemResponse> {
    if (this.#pairing === null || this.#pairing.pollToken !== input.pollToken || this.#pairing.userCode !== input.userCode) {
      return Promise.reject(new ApiFailure("unavailable", false));
    }
    if (!this.approved) return Promise.resolve({ pairingExpiresAt: this.seconds + 600, state: "pending" });
    return Promise.resolve({ permit: this.#permit, permitExpiresAt: this.seconds + 600, serverTime: this.seconds, state: "approved" });
  }

  permitStatus(permit?: string): Promise<CreatePermitStatusResponse> {
    if (permit !== this.#permit || this.permitUsed) return Promise.reject(new ApiFailure("creation_permit_required", false));
    return Promise.resolve({ permitExpiresAt: this.seconds + 600, serverTime: this.seconds, state: "unused" });
  }

  #consumePermit(permit: string | undefined): void {
    if (permit !== this.#permit || this.permitUsed) throw new ApiFailure("creation_permit_required", false);
    this.permitUsed = true;
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
  expect(created.output).toMatchObject({ action: "pair", pairUrl: "https://kryptex.example/pair#ABCD-EFGH", state: "pairing", userCode: "ABCD-EFGH" });
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
