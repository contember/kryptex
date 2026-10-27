import type { RequestFieldType } from "@kryptex/contracts/payloads";
import { isTtlSeconds, type TtlSeconds } from "@kryptex/contracts/protocol";
import type { ErrorCode } from "./errors.js";
import {
  arrayValue,
  base64UrlText,
  base64UrlValue,
  booleanValue,
  exactObject,
  field,
  integerValue,
  literal,
  nullable,
  ShapeError,
  stringValue
} from "./validate.js";

export type Dialect = "expand" | "literal";

/** Paths are stored relative to the project root and resolved again before every use. */
export type RequestSink =
  | { readonly dialect: Dialect; readonly kind: "env"; readonly path: string }
  | { readonly argv: readonly string[]; readonly kind: "exec" };

export interface StoredField {
  readonly help: string;
  readonly id: string;
  readonly label: string;
  readonly required: boolean;
  readonly target: string | null;
  readonly type: RequestFieldType;
}

export interface Pairing {
  readonly pairingExpiresAt: number;
  readonly pollToken: string;
  readonly userCode: string;
}

export interface RequestAttempt {
  readonly attemptId: string;
  readonly clientNotAfter: number;
  readonly envelope: string;
  readonly locator: string;
  readonly ownerSeed: string;
  readonly schemaDigest: string;
  readonly settleNotAfter: number;
  readonly writeSeed: string;
}

export interface CreatedRequest {
  readonly clientNotAfter: number;
  readonly locator: string;
  readonly ownerSeed: string;
  readonly schemaDigest: string;
  readonly serverExpiresAt: number;
  readonly writeSeed: string;
}

export type Delivered =
  | { readonly keys: readonly string[]; readonly kind: "env"; readonly path: string }
  | { readonly command: string; readonly exitCode: number; readonly keys: readonly string[]; readonly kind: "exec" };

export type RequestPhase =
  | { readonly name: "pairing"; readonly pairing: Pairing }
  | { readonly attempt: RequestAttempt | null; readonly name: "creating"; readonly permit: string }
  | { readonly name: "waiting"; readonly reported: boolean; readonly request: CreatedRequest }
  | { readonly name: "picking"; readonly request: CreatedRequest }
  | { readonly name: "received"; readonly request: CreatedRequest; readonly response: string }
  | { readonly delivered: Delivered; readonly name: "delivered"; readonly receipt: string }
  | { readonly error: ErrorCode; readonly name: "failed" };

export interface SendAttempt {
  readonly attemptId: string;
  readonly clientNotAfter: number;
  readonly envelope: string;
  readonly locator: string;
  readonly manageSeed: string;
  readonly secondKey: string;
  readonly sendSeed: string;
  readonly settleNotAfter: number;
}

export interface CreatedSend {
  readonly locator: string;
  readonly manageSeed: string;
  readonly secondKey: string;
  readonly sendSeed: string;
  readonly serverExpiresAt: number;
}

export type SendPhase =
  | { readonly name: "pairing"; readonly pairing: Pairing }
  | { readonly attempt: SendAttempt | null; readonly name: "creating"; readonly permit: string }
  | { readonly name: "handoff"; readonly send: CreatedSend }
  | { readonly name: "created"; readonly recipientUrl: string; readonly reported: boolean; readonly serverExpiresAt: number }
  | { readonly error: ErrorCode; readonly name: "failed" };

interface CommonRecord {
  readonly createdAt: number;
  readonly cwd: string;
  readonly handle: string;
  readonly origin: string;
  readonly projectRoot: string;
  readonly version: 1;
}

export interface RequestRecord extends CommonRecord {
  readonly fields: readonly StoredField[];
  readonly kind: "request";
  readonly phase: RequestPhase;
  readonly sink: RequestSink;
  readonly title: string;
  readonly ttl: TtlSeconds;
}

export interface SendSource {
  readonly dialect: Dialect;
  readonly keys: readonly string[];
  readonly path: string;
}

export interface SendRecord extends CommonRecord {
  readonly handoffPath: string;
  readonly kind: "send";
  readonly maxRetrievals: number;
  readonly phase: SendPhase;
  readonly source: SendSource;
  readonly ttl: TtlSeconds;
}

export type OperationRecord = RequestRecord | SendRecord;

const ERROR_CODES: readonly ErrorCode[] = [
  "busy", "network", "rate_limited", "unavailable", "expired", "revoked", "pickup_lost", "answer_invalid", "target_invalid",
  "env_file_conflict", "env_value_unrepresentable", "source_invalid", "exec_failed", "handoff_failed", "state_invalid", "internal"
];
const FIELD_TYPES: readonly RequestFieldType[] = ["secret", "text", "long-secret", "long-text", "instruction"];

function ttl(value: unknown): TtlSeconds {
  const seconds = integerValue(value, "ttl");
  if (!isTtlSeconds(seconds)) throw new ShapeError("ttl");
  return seconds;
}

function stringList(value: unknown, context: string): readonly string[] {
  return arrayValue(value, context).map((entry) => stringValue(entry, context));
}

function parsePairing(value: unknown): Pairing {
  const object = exactObject(value, ["pairingExpiresAt", "pollToken", "userCode"], "pairing");
  return {
    pairingExpiresAt: integerValue(field(object, "pairingExpiresAt"), "pairing.pairingExpiresAt"),
    pollToken: base64UrlValue(field(object, "pollToken"), 32, "pairing.pollToken"),
    userCode: stringValue(field(object, "userCode"), "pairing.userCode")
  };
}

function parseRequestAttempt(value: unknown): RequestAttempt {
  const keys = ["attemptId", "clientNotAfter", "envelope", "locator", "ownerSeed", "schemaDigest", "settleNotAfter", "writeSeed"];
  const object = exactObject(value, keys, "request attempt");
  return {
    attemptId: base64UrlValue(field(object, "attemptId"), 16, "attemptId"),
    clientNotAfter: integerValue(field(object, "clientNotAfter"), "clientNotAfter"),
    envelope: base64UrlText(field(object, "envelope"), "envelope"),
    locator: base64UrlValue(field(object, "locator"), 16, "locator"),
    ownerSeed: base64UrlValue(field(object, "ownerSeed"), 32, "ownerSeed"),
    schemaDigest: base64UrlValue(field(object, "schemaDigest"), 32, "schemaDigest"),
    settleNotAfter: integerValue(field(object, "settleNotAfter"), "settleNotAfter"),
    writeSeed: base64UrlValue(field(object, "writeSeed"), 32, "writeSeed")
  };
}

function parseCreatedRequest(value: unknown): CreatedRequest {
  const object = exactObject(value, ["clientNotAfter", "locator", "ownerSeed", "schemaDigest", "serverExpiresAt", "writeSeed"], "request");
  return {
    clientNotAfter: integerValue(field(object, "clientNotAfter"), "clientNotAfter"),
    locator: base64UrlValue(field(object, "locator"), 16, "locator"),
    ownerSeed: base64UrlValue(field(object, "ownerSeed"), 32, "ownerSeed"),
    schemaDigest: base64UrlValue(field(object, "schemaDigest"), 32, "schemaDigest"),
    serverExpiresAt: integerValue(field(object, "serverExpiresAt"), "serverExpiresAt"),
    writeSeed: base64UrlValue(field(object, "writeSeed"), 32, "writeSeed")
  };
}

function parseDelivered(value: unknown): Delivered {
  if (typeof value === "object" && value !== null && Reflect.get(value, "kind") === "env") {
    const object = exactObject(value, ["keys", "kind", "path"], "delivered");
    return { keys: stringList(field(object, "keys"), "delivered.keys"), kind: "env", path: stringValue(field(object, "path"), "delivered.path") };
  }
  const object = exactObject(value, ["command", "exitCode", "keys", "kind"], "delivered");
  literal(field(object, "kind"), ["exec"], "delivered.kind");
  return {
    command: stringValue(field(object, "command"), "delivered.command"),
    exitCode: integerValue(field(object, "exitCode"), "delivered.exitCode"),
    keys: stringList(field(object, "keys"), "delivered.keys"),
    kind: "exec"
  };
}

function phaseName<const T extends string>(value: unknown, names: readonly T[]): T {
  if (typeof value !== "object" || value === null) throw new ShapeError("phase");
  return literal(Reflect.get(value, "name"), names, "phase.name");
}

function parseRequestPhase(value: unknown): RequestPhase {
  const name = phaseName(value, ["pairing", "creating", "waiting", "picking", "received", "delivered", "failed"]);
  if (name === "pairing") {
    return { name, pairing: parsePairing(field(exactObject(value, ["name", "pairing"], "phase"), "pairing")) };
  }
  if (name === "creating") {
    const object = exactObject(value, ["attempt", "name", "permit"], "phase");
    return { attempt: nullable(field(object, "attempt"), parseRequestAttempt), name, permit: stringValue(field(object, "permit"), "permit") };
  }
  if (name === "waiting") {
    const object = exactObject(value, ["name", "reported", "request"], "phase");
    return { name, reported: booleanValue(field(object, "reported"), "reported"), request: parseCreatedRequest(field(object, "request")) };
  }
  if (name === "picking") {
    return { name, request: parseCreatedRequest(field(exactObject(value, ["name", "request"], "phase"), "request")) };
  }
  if (name === "received") {
    const object = exactObject(value, ["name", "request", "response"], "phase");
    return { name, request: parseCreatedRequest(field(object, "request")), response: base64UrlText(field(object, "response"), "response") };
  }
  if (name === "delivered") {
    const object = exactObject(value, ["delivered", "name", "receipt"], "phase");
    return { delivered: parseDelivered(field(object, "delivered")), name, receipt: stringValue(field(object, "receipt"), "receipt") };
  }
  return { error: literal(field(exactObject(value, ["error", "name"], "phase"), "error"), ERROR_CODES, "error"), name };
}

function parseSendAttempt(value: unknown): SendAttempt {
  const keys = ["attemptId", "clientNotAfter", "envelope", "locator", "manageSeed", "secondKey", "sendSeed", "settleNotAfter"];
  const object = exactObject(value, keys, "send attempt");
  return {
    attemptId: base64UrlValue(field(object, "attemptId"), 16, "attemptId"),
    clientNotAfter: integerValue(field(object, "clientNotAfter"), "clientNotAfter"),
    envelope: base64UrlText(field(object, "envelope"), "envelope"),
    locator: base64UrlValue(field(object, "locator"), 16, "locator"),
    manageSeed: base64UrlValue(field(object, "manageSeed"), 32, "manageSeed"),
    secondKey: base64UrlValue(field(object, "secondKey"), 16, "secondKey"),
    sendSeed: base64UrlValue(field(object, "sendSeed"), 32, "sendSeed"),
    settleNotAfter: integerValue(field(object, "settleNotAfter"), "settleNotAfter")
  };
}

function parseCreatedSend(value: unknown): CreatedSend {
  const object = exactObject(value, ["locator", "manageSeed", "secondKey", "sendSeed", "serverExpiresAt"], "send");
  return {
    locator: base64UrlValue(field(object, "locator"), 16, "locator"),
    manageSeed: base64UrlValue(field(object, "manageSeed"), 32, "manageSeed"),
    secondKey: base64UrlValue(field(object, "secondKey"), 16, "secondKey"),
    sendSeed: base64UrlValue(field(object, "sendSeed"), 32, "sendSeed"),
    serverExpiresAt: integerValue(field(object, "serverExpiresAt"), "serverExpiresAt")
  };
}

function parseSendPhase(value: unknown): SendPhase {
  const name = phaseName(value, ["pairing", "creating", "handoff", "created", "failed"]);
  if (name === "pairing") {
    return { name, pairing: parsePairing(field(exactObject(value, ["name", "pairing"], "phase"), "pairing")) };
  }
  if (name === "creating") {
    const object = exactObject(value, ["attempt", "name", "permit"], "phase");
    return { attempt: nullable(field(object, "attempt"), parseSendAttempt), name, permit: stringValue(field(object, "permit"), "permit") };
  }
  if (name === "handoff") {
    return { name, send: parseCreatedSend(field(exactObject(value, ["name", "send"], "phase"), "send")) };
  }
  if (name === "created") {
    const object = exactObject(value, ["name", "recipientUrl", "reported", "serverExpiresAt"], "phase");
    return {
      name,
      recipientUrl: stringValue(field(object, "recipientUrl"), "recipientUrl"),
      reported: booleanValue(field(object, "reported"), "reported"),
      serverExpiresAt: integerValue(field(object, "serverExpiresAt"), "serverExpiresAt")
    };
  }
  return { error: literal(field(exactObject(value, ["error", "name"], "phase"), "error"), ERROR_CODES, "error"), name };
}

function parseStoredField(value: unknown): StoredField {
  const object = exactObject(value, ["help", "id", "label", "required", "target", "type"], "field");
  return {
    help: stringValue(field(object, "help"), "field.help"),
    id: stringValue(field(object, "id"), "field.id"),
    label: stringValue(field(object, "label"), "field.label"),
    required: booleanValue(field(object, "required"), "field.required"),
    target: nullable(field(object, "target"), (entry) => stringValue(entry, "field.target")),
    type: literal(field(object, "type"), FIELD_TYPES, "field.type")
  };
}

function parseSink(value: unknown): RequestSink {
  if (typeof value === "object" && value !== null && Reflect.get(value, "kind") === "env") {
    const object = exactObject(value, ["dialect", "kind", "path"], "sink");
    return { dialect: literal(field(object, "dialect"), ["expand", "literal"], "sink.dialect"), kind: "env", path: stringValue(field(object, "path"), "sink.path") };
  }
  const object = exactObject(value, ["argv", "kind"], "sink");
  literal(field(object, "kind"), ["exec"], "sink.kind");
  const argv = stringList(field(object, "argv"), "sink.argv");
  if (argv.length === 0) throw new ShapeError("sink.argv");
  return { argv, kind: "exec" };
}

export const RECORD_VERSION = 1;

const COMMON_KEYS = ["createdAt", "cwd", "handle", "kind", "origin", "phase", "projectRoot", "version"];

export function parseRecord(value: unknown): OperationRecord {
  if (typeof value !== "object" || value === null) throw new ShapeError("record");
  const kind = literal(Reflect.get(value, "kind"), ["request", "send"], "record.kind");
  const object = kind === "request"
    ? exactObject(value, [...COMMON_KEYS, "fields", "sink", "title", "ttl"], "record")
    : exactObject(value, [...COMMON_KEYS, "handoffPath", "maxRetrievals", "source", "ttl"], "record");
  const common: CommonRecord = {
    createdAt: integerValue(field(object, "createdAt"), "createdAt"),
    cwd: stringValue(field(object, "cwd"), "cwd"),
    handle: stringValue(field(object, "handle"), "handle"),
    origin: stringValue(field(object, "origin"), "origin"),
    projectRoot: stringValue(field(object, "projectRoot"), "projectRoot"),
    version: RECORD_VERSION
  };
  if (field(object, "version") !== RECORD_VERSION) throw new ShapeError("version");
  if (kind === "request") {
    return {
      ...common,
      fields: arrayValue(field(object, "fields"), "fields").map(parseStoredField),
      kind,
      phase: parseRequestPhase(field(object, "phase")),
      sink: parseSink(field(object, "sink")),
      title: stringValue(field(object, "title"), "title"),
      ttl: ttl(field(object, "ttl"))
    };
  }
  const source = exactObject(field(object, "source"), ["dialect", "keys", "path"], "source");
  return {
    ...common,
    handoffPath: stringValue(field(object, "handoffPath"), "handoffPath"),
    kind,
    maxRetrievals: integerValue(field(object, "maxRetrievals"), "maxRetrievals"),
    phase: parseSendPhase(field(object, "phase")),
    source: {
      dialect: literal(field(source, "dialect"), ["expand", "literal"], "source.dialect"),
      keys: stringList(field(source, "keys"), "source.keys"),
      path: stringValue(field(source, "path"), "source.path")
    },
    ttl: ttl(field(object, "ttl"))
  };
}
