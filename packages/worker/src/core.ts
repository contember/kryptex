import { decodeCanonicalBase64Url } from "./strict.js";

const encoder = new TextEncoder();

const CAPABILITY_PREFIX = encoder.encode("kryptex/v1/server-capability-tag");
const RATE_LIMIT_PREFIX = encoder.encode("kryptex/v1/rate-limit-locator");
const PERMIT_ISSUANCE_LABEL = "kryptex/v1/create-permit/issuance";
const PERMIT_LOCATOR_LABEL = "kryptex/v1/create-permit/locator";
const PERMIT_TOKEN_LABEL = "kryptex/v1/create-permit/token";

export const ZERO_TAG = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

export interface PermitMaterial {
  readonly locator: Uint8Array;
  readonly permitSeed: Uint8Array;
  readonly token: Uint8Array;
}

export function unixSeconds(nowMs = Date.now()): number {
  return Math.floor(nowMs / 1000);
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return encodeBase64Url(bytes);
}

export function byteArraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

async function importHmacKey(key: Uint8Array, usage: "sign" | "verify"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBuffer(key), { hash: "SHA-256", name: "HMAC" }, false, [usage]);
}

export async function hmacSign(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await importHmacKey(key, "sign");
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, toBuffer(message)));
}

export async function hmacVerify(key: Uint8Array, tag: Uint8Array, message: Uint8Array): Promise<boolean> {
  const cryptoKey = await importHmacKey(key, "verify");
  return crypto.subtle.verify("HMAC", cryptoKey, toBuffer(tag), toBuffer(message));
}

export function capabilityMessage(
  resourceKind: 1 | 2 | 3,
  capabilityKind: 1 | 2 | 3,
  locator: Uint8Array,
  token: Uint8Array
): Uint8Array {
  return concatenate([CAPABILITY_PREFIX, new Uint8Array([0, resourceKind, capabilityKind]), locator, token]);
}

export async function capabilityTag(
  key: Uint8Array,
  resourceKind: 1 | 2 | 3,
  capabilityKind: 1 | 2 | 3,
  locator: Uint8Array,
  token: Uint8Array
): Promise<string> {
  return encodeBase64Url(await hmacSign(key, capabilityMessage(resourceKind, capabilityKind, locator, token)));
}

export async function verifyCapabilityTag(
  key: Uint8Array,
  tag: string,
  resourceKind: 1 | 2 | 3,
  capabilityKind: 1 | 2 | 3,
  locator: Uint8Array,
  token: Uint8Array
): Promise<boolean> {
  const tagBytes = decodeCanonicalBase64Url(tag, 32, "capability tag");
  return hmacVerify(key, tagBytes, capabilityMessage(resourceKind, capabilityKind, locator, token));
}

export async function blindedLocator(
  key: Uint8Array,
  resourceKind: 1 | 2 | 3,
  locator: Uint8Array
): Promise<string> {
  const message = concatenate([RATE_LIMIT_PREFIX, new Uint8Array([0, resourceKind]), locator]);
  return encodeBase64Url(await hmacSign(key, message));
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toBuffer(bytes)));
}

export async function digestBase64Url(bytes: Uint8Array): Promise<string> {
  return encodeBase64Url(await sha256(bytes));
}

async function hkdfExtract(label: string, input: Uint8Array): Promise<Uint8Array> {
  return hmacSign(await sha256(encoder.encode(label)), input);
}

async function hkdfExpand(prk: Uint8Array, label: string, length: number): Promise<Uint8Array> {
  const block = await hmacSign(prk, concatenate([encoder.encode(label), new Uint8Array([1])]));
  return block.slice(0, length);
}

export async function derivePermitMaterial(issuanceKey: Uint8Array, requestIdBytes: Uint8Array): Promise<PermitMaterial> {
  const permitSeed = await hmacSign(
    issuanceKey,
    concatenate([encoder.encode(PERMIT_ISSUANCE_LABEL), new Uint8Array([0]), requestIdBytes])
  );
  const derived = await derivePermitFromSeed(permitSeed);
  return {
    locator: derived.locator,
    permitSeed,
    token: derived.token
  };
}

export async function derivePermitFromSeed(seed: Uint8Array): Promise<{ readonly locator: Uint8Array; readonly token: Uint8Array }> {
  const prk = await hkdfExtract(PERMIT_LOCATOR_LABEL, seed);
  return {
    locator: await hkdfExpand(prk, PERMIT_LOCATOR_LABEL, 16),
    token: await hkdfExpand(prk, PERMIT_TOKEN_LABEL, 32)
  };
}

export function decodeUuid(uuid: string): Uint8Array {
  const compact = uuid.replaceAll("-", "");
  const bytes = new Uint8Array(16);
  for (let index = 0; index < bytes.byteLength; index += 1) {
    const pair = compact.slice(index * 2, index * 2 + 2);
    bytes[index] = Number.parseInt(pair, 16);
  }
  return bytes;
}
