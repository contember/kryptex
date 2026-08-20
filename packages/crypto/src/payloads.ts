import {
  parseRequestResponsePayload,
  parseRequestSchemaPayload,
  parseSendPayload,
  serializeCanonicalPayload,
  type CanonicalPayload,
  type RequestResponsePayload,
  type RequestSchemaPayload,
  type SendPayload
} from "@kryptex/contracts/payloads";
import { equalBytes, strictUtf8, utf8 } from "./bytes.js";
import { fail } from "./errors.js";

function parseJson(bytes: Uint8Array): unknown {
  try {
    const parsed: unknown = JSON.parse(strictUtf8(bytes));
    return parsed;
  } catch {
    return fail("invalid_payload");
  }
}

function requireCanonical<T extends CanonicalPayload>(bytes: Uint8Array, payload: T): T {
  if (!equalBytes(bytes, utf8(serializeCanonicalPayload(payload)))) fail("invalid_payload");
  return payload;
}

export function encodePayload(payload: CanonicalPayload): Uint8Array<ArrayBuffer> {
  let validated: CanonicalPayload;
  try {
    if (payload.kind === "text" || payload.kind === "fields") validated = parseSendPayload(payload);
    else if (payload.kind === "request-schema") validated = parseRequestSchemaPayload(payload);
    else validated = parseRequestResponsePayload(payload);
  } catch {
    return fail("invalid_payload");
  }
  return utf8(serializeCanonicalPayload(validated));
}

export function decodeSendPayload(bytes: Uint8Array): SendPayload {
  try {
    return requireCanonical(bytes, parseSendPayload(parseJson(bytes)));
  } catch {
    return fail("invalid_payload");
  }
}

export function decodeRequestSchemaPayload(bytes: Uint8Array): RequestSchemaPayload {
  try {
    return requireCanonical(bytes, parseRequestSchemaPayload(parseJson(bytes)));
  } catch {
    return fail("invalid_payload");
  }
}

export function decodeRequestResponsePayload(
  bytes: Uint8Array,
  trustedSchema?: RequestSchemaPayload
): RequestResponsePayload {
  try {
    return requireCanonical(bytes, parseRequestResponsePayload(parseJson(bytes), trustedSchema));
  } catch {
    return fail("invalid_payload");
  }
}
