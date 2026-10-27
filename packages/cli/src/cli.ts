import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { parseArgs } from "node:util";
import { parseRequestSchemaPayload } from "@kryptex/contracts/payloads";
import { isTtlSeconds, MAX_FIELDS, MAX_LABEL_UTF8_BYTES, type TtlSeconds } from "@kryptex/contracts/protocol";
import { encodeBase64Url } from "@kryptex/crypto";
import { checkDotenvTargets, readDotenvKeys } from "./dotenv.js";
import { CliError, UsageError } from "./errors.js";
import { errorOutcome, nowSeconds, pairingOutcome, startPairing, type FlowContext, type NativeClient, type Outcome } from "./flow.js";
import { checkProjectPath, projectPath, projectRoot, readProjectFile } from "./project.js";
import { RECORD_VERSION, type Dialect, type OperationRecord, type RequestRecord, type RequestSink, type SendRecord, type StoredField } from "./record.js";
import { advanceRequest, revokeRequest } from "./request-flow.js";
import { advanceSend, revokeSend } from "./send-flow.js";
import { AGENT_INSTRUCTIONS } from "./skill.js";
import { acquireLock, deleteRecord, isHandle, listHandles, newHandle, openStore, readRecord, stateDirectory, writeRecord } from "./store.js";
import { arrayValue, booleanValue, exactObject, field, literal, ShapeError, stringValue } from "./validate.js";

export interface Runtime {
  readonly clientFor: (origin: string) => NativeClient;
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly now: () => number;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly stderr: (chunk: Buffer) => void;
}

export type CommandResult = Outcome | { readonly exitCode: 0; readonly text: string };

const USAGE = "Usage: kryptex request create | send create | wait <handle> | list | discard <handle> | skill. Run kryptex skill for instructions.";
const TARGET_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const DEFAULT_TTL: TtlSeconds = 604800;
const MAX_SPEC_BYTES = 65536;

function utf8Length(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

export function parseOrigin(input: string | undefined): string {
  if (input === undefined || input.length === 0) throw new UsageError("--origin or KRYPTEX_ORIGIN is required.");
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UsageError("The origin must be an https: origin or http://localhost.");
  }
  const local = url.protocol === "http:" && url.hostname === "localhost";
  if ((url.protocol !== "https:" && !local) || url.username !== "" || url.password !== "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    throw new UsageError("The origin must be an https: origin or http://localhost.");
  }
  return url.origin;
}

function parseTtl(input: string | undefined): TtlSeconds {
  if (input === undefined) return DEFAULT_TTL;
  const seconds = /^[0-9]{1,8}$/u.test(input) ? Number(input) : Number.NaN;
  if (!isTtlSeconds(seconds)) throw new UsageError("--ttl must be one of the protocol TTL values.");
  return seconds;
}

function parseIntegerOption(input: string | undefined, fallback: number, minimum: number, maximum: number, message: string): number {
  if (input === undefined) return fallback;
  const value = /^[0-9]{1,4}$/u.test(input) ? Number(input) : Number.NaN;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new UsageError(message);
  return value;
}

function parseDialect(input: string | undefined): Dialect {
  if (input === "expand" || input === "literal") return input;
  throw new UsageError("--env-dialect must be expand or literal.");
}

function fieldId(index: number): string {
  return `field${String(index + 1).padStart(3, "0")}`;
}

/** Parses the form spec and checks the result against the protocol schema rules before anything is recorded. */
export function parseFormSpec(text: string): { readonly fields: readonly StoredField[]; readonly title: string } {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new UsageError("The form spec is not valid JSON.");
  }
  let title: string;
  let fields: StoredField[];
  try {
    const object = exactObject(value, ["fields", "title"], "spec");
    title = stringValue(field(object, "title"), "title");
    fields = arrayValue(field(object, "fields"), "fields").map((entry, index): StoredField => {
      const type: unknown = typeof entry === "object" && entry !== null ? Reflect.get(entry, "type") : undefined;
      const instruction = type === "instruction";
      const keys = instruction ? ["help", "label", "required", "type"] : ["help", "label", "required", "target", "type"];
      const spec = exactObject(entry, keys, "field");
      return {
        help: stringValue(field(spec, "help"), "help"),
        id: fieldId(index),
        label: stringValue(field(spec, "label"), "label"),
        required: booleanValue(field(spec, "required"), "required"),
        target: instruction ? null : stringValue(field(spec, "target"), "target"),
        type: literal(field(spec, "type"), ["secret", "text", "long-secret", "long-text", "instruction"], "type")
      };
    });
  } catch (error) {
    if (error instanceof ShapeError) throw new UsageError("The form spec does not match the documented shape.");
    throw error;
  }
  const targets = fields.flatMap((entry) => entry.target === null ? [] : [entry.target]);
  if (targets.length === 0) throw new UsageError("The form spec needs at least one field with a target.");
  if (targets.some((target) => !TARGET_PATTERN.test(target) || utf8Length(target) > 128) || new Set(targets).size !== targets.length) {
    throw new UsageError("Every target must match [A-Za-z_][A-Za-z0-9_]*, be at most 128 bytes, and be unique.");
  }
  try {
    parseRequestSchemaPayload({
      fields: fields.map((entry) => ({ help: entry.help, id: entry.id, label: entry.label, required: entry.required, type: entry.type })),
      kind: "request-schema",
      recipientPublicKey: encodeBase64Url(new Uint8Array(32)),
      title
    });
  } catch {
    throw new UsageError("The form spec breaks a protocol rule: title 1-120 bytes, 1-32 fields, label 1-120 bytes, help up to 500 bytes, instructions not required.");
  }
  return { fields, title };
}

function readSpecFile(cwd: string, path: string): string {
  let bytes: Buffer;
  try {
    bytes = readFileSync(resolve(cwd, path));
  } catch {
    throw new UsageError("The form spec cannot be read.");
  }
  if (bytes.byteLength > MAX_SPEC_BYTES) throw new UsageError("The form spec is larger than 64 KiB.");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new UsageError("The form spec is not UTF-8.");
  }
}

/** Splits off the command after `--`, which only `--exec` takes. */
function splitCommand(argv: readonly string[]): { readonly command: readonly string[] | null; readonly options: readonly string[] } {
  const separator = argv.indexOf("--");
  return separator < 0 ? { command: null, options: argv } : { command: argv.slice(separator + 1), options: argv.slice(0, separator) };
}

function parseOptions<const T extends Readonly<Record<string, { readonly multiple?: boolean; readonly type: "boolean" | "string" }>>>(args: readonly string[], options: T) {
  try {
    return parseArgs({ allowPositionals: false, args: [...args], options, strict: true }).values;
  } catch {
    throw new UsageError(USAGE);
  }
}

function positional(args: readonly string[]): { readonly handle: string; readonly rest: readonly string[] } {
  const [handle, ...rest] = args;
  if (handle === undefined || !isHandle(handle)) throw new UsageError("A valid operation handle is required.");
  return { handle, rest };
}

async function requestCreate(args: readonly string[], runtime: Runtime): Promise<Outcome> {
  const { command, options } = splitCommand(args);
  const values = parseOptions(options, {
    "env-dialect": { type: "string" },
    "env-file": { type: "string" },
    exec: { type: "boolean" },
    origin: { type: "string" },
    spec: { type: "string" },
    ttl: { type: "string" }
  });
  const origin = parseOrigin(values.origin ?? runtime.environment["KRYPTEX_ORIGIN"]);
  if (values.spec === undefined) throw new UsageError("--spec is required.");
  const spec = parseFormSpec(readSpecFile(runtime.cwd, values.spec));
  const ttl = parseTtl(values.ttl);
  const exec = values.exec === true;
  if (exec === (values["env-file"] !== undefined)) throw new UsageError("Pass exactly one of --env-file or --exec.");
  if (exec !== (command !== null && command.length > 0)) throw new UsageError("--exec needs a command after --, and only --exec takes one.");
  if (exec && values["env-dialect"] !== undefined) throw new UsageError("--env-dialect applies only to --env-file.");
  const root = projectRoot(runtime.cwd);
  let sink: RequestSink;
  if (values["env-file"] !== undefined) {
    const dialect = parseDialect(values["env-dialect"]);
    const path = projectPath(root, runtime.cwd, values["env-file"]);
    const existing = readProjectFile(checkProjectPath(root, path, { existence: "either", output: true }));
    if (existing !== null) checkDotenvTargets(existing, spec.fields.flatMap((entry) => entry.target === null ? [] : [entry.target]));
    sink = { dialect, kind: "env", path };
  } else {
    sink = { argv: command ?? [], kind: "exec" };
  }
  const store = openStore(stateDirectory(runtime.environment));
  const pairing = await startPairing(runtime.clientFor(origin));
  const record: RequestRecord = {
    createdAt: nowSeconds(runtime),
    cwd: runtime.cwd,
    fields: spec.fields,
    handle: newHandle(),
    kind: "request",
    origin,
    phase: { name: "pairing", pairing },
    projectRoot: root,
    sink,
    title: spec.title,
    ttl,
    version: RECORD_VERSION
  };
  writeRecord(store, record);
  return pairingOutcome(record, pairing, 3);
}

async function sendCreate(args: readonly string[], runtime: Runtime): Promise<Outcome> {
  const values = parseOptions(args, {
    "env-dialect": { type: "string" },
    "from-env-file": { type: "string" },
    "handoff-file": { type: "string" },
    key: { multiple: true, type: "string" },
    "max-retrievals": { type: "string" },
    origin: { type: "string" },
    ttl: { type: "string" }
  });
  const origin = parseOrigin(values.origin ?? runtime.environment["KRYPTEX_ORIGIN"]);
  if (values["from-env-file"] === undefined) throw new UsageError("--from-env-file is required.");
  if (values["handoff-file"] === undefined) throw new UsageError("--handoff-file is required.");
  const dialect = parseDialect(values["env-dialect"]);
  const keys = values.key ?? [];
  if (keys.length === 0 || keys.length > MAX_FIELDS || new Set(keys).size !== keys.length) {
    throw new UsageError("Pass 1 to 32 distinct --key options.");
  }
  if (keys.some((key) => !TARGET_PATTERN.test(key) || utf8Length(key) > MAX_LABEL_UTF8_BYTES)) {
    throw new UsageError("Every --key must match [A-Za-z_][A-Za-z0-9_]* and be at most 120 bytes.");
  }
  const ttl = parseTtl(values.ttl);
  const maxRetrievals = parseIntegerOption(values["max-retrievals"], 1, 1, 10, "--max-retrievals must be 1 through 10.");
  const root = projectRoot(runtime.cwd);
  const sourcePath = projectPath(root, runtime.cwd, values["from-env-file"]);
  const handoffPath = projectPath(root, runtime.cwd, values["handoff-file"]);
  if (sourcePath === handoffPath) throw new UsageError("The source and the hand-off file must differ.");
  const content = readProjectFile(checkProjectPath(root, sourcePath, { existence: "required", output: false }));
  if (content === null) throw new CliError("source_invalid");
  readDotenvKeys(content, dialect, keys);
  checkProjectPath(root, handoffPath, { existence: "absent", output: true });
  const store = openStore(stateDirectory(runtime.environment));
  const pairing = await startPairing(runtime.clientFor(origin));
  const record: SendRecord = {
    createdAt: nowSeconds(runtime),
    cwd: runtime.cwd,
    handle: newHandle(),
    handoffPath,
    kind: "send",
    maxRetrievals,
    origin,
    phase: { name: "pairing", pairing },
    projectRoot: root,
    source: { dialect, keys, path: sourcePath },
    ttl,
    version: RECORD_VERSION
  };
  writeRecord(store, record);
  return pairingOutcome(record, pairing, 3);
}

function withOperationLock<T>(store: string, handle: string, action: () => Promise<T>): Promise<T> {
  const release = acquireLock(store, `op-${handle}`);
  return action().finally(release);
}

async function wait(args: readonly string[], runtime: Runtime): Promise<Outcome> {
  const { handle, rest } = positional(args);
  const values = parseOptions(rest, { timeout: { type: "string" } });
  const timeout = parseIntegerOption(values.timeout, 90, 1, 3600, "--timeout must be 1 through 3600 seconds.");
  const store = openStore(stateDirectory(runtime.environment));
  return withOperationLock(store, handle, async () => {
    const record = readRecord(store, handle);
    const context: FlowContext = {
      client: runtime.clientFor(record.origin),
      deadline: runtime.now() + timeout * 1_000,
      now: runtime.now,
      sleep: runtime.sleep,
      stderr: runtime.stderr,
      store
    };
    return record.kind === "request" ? advanceRequest(context, record) : advanceSend(context, record);
  });
}

function expiresAt(record: OperationRecord): number | null {
  const phase = record.phase;
  if (phase.name === "waiting" || phase.name === "picking" || phase.name === "received") return phase.request.serverExpiresAt;
  if (phase.name === "handoff") return phase.send.serverExpiresAt;
  if (phase.name === "created") return phase.serverExpiresAt;
  return null;
}

function target(record: OperationRecord): string {
  if (record.kind === "send") return record.handoffPath;
  return record.sink.kind === "env" ? record.sink.path : basename(record.sink.argv[0] ?? "");
}

function list(args: readonly string[], runtime: Runtime): Outcome {
  parseOptions(args, {});
  const store = openStore(stateDirectory(runtime.environment));
  const operations = listHandles(store).map((handle) => {
    let record: OperationRecord;
    try {
      record = readRecord(store, handle);
    } catch {
      return { handle, state: "invalid" };
    }
    return { expiresAt: expiresAt(record), handle, kind: record.kind, origin: record.origin, state: record.phase.name, target: target(record) };
  });
  return { exitCode: 0, output: { operations } };
}

async function discard(args: readonly string[], runtime: Runtime): Promise<Outcome> {
  const { handle, rest } = positional(args);
  const force = parseOptions(rest, { force: { type: "boolean" } }).force === true;
  const store = openStore(stateDirectory(runtime.environment));
  return withOperationLock(store, handle, async () => {
    let revoked = false;
    try {
      const record = readRecord(store, handle);
      const context = { client: runtime.clientFor(record.origin) };
      revoked = record.kind === "request" ? await revokeRequest(context, record) : await revokeSend(context, record);
    } catch (error) {
      if (!force) throw error;
    }
    try {
      deleteRecord(store, handle);
    } catch {
      throw new CliError("state_invalid");
    }
    return { exitCode: 0, output: { discarded: true, handle, revoked } };
  });
}

async function dispatch(argv: readonly string[], runtime: Runtime): Promise<CommandResult> {
  const [command, subcommand, ...rest] = argv;
  if (command === "request" && subcommand === "create") return requestCreate(rest, runtime);
  if (command === "send" && subcommand === "create") return sendCreate(rest, runtime);
  const args = argv.slice(1);
  if (command === "wait") return wait(args, runtime);
  if (command === "list") return list(args, runtime);
  if (command === "discard") return discard(args, runtime);
  if (command === "skill" && args.length === 0) return { exitCode: 0, text: AGENT_INSTRUCTIONS };
  throw new UsageError(USAGE);
}

/** Runs one command. Every failure becomes a fixed code; exception text never reaches the output. */
export async function run(argv: readonly string[], runtime: Runtime): Promise<CommandResult> {
  const candidate = argv[0] === "wait" || argv[0] === "discard" ? argv[1] : undefined;
  const handle = candidate !== undefined && isHandle(candidate) ? candidate : null;
  try {
    return await dispatch(argv, runtime);
  } catch (error) {
    if (error instanceof UsageError) return { exitCode: 2, output: { error: "usage", message: error.message } };
    if (error instanceof CliError) return errorOutcome(handle, error.code);
    return errorOutcome(handle, "internal");
  }
}
