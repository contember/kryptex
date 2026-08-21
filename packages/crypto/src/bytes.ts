import { fail } from "./errors.js";

const textEncoder = new TextEncoder();

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  if (!value.isWellFormed()) fail("invalid_unicode");
  return textEncoder.encode(value);
}

export function strictUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return fail("invalid_utf8");
  }
}

export function owned(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function concat(...values: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.byteLength, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function requireLength(bytes: Uint8Array, length: number, code = "invalid_length"): void {
  if (bytes.byteLength !== length) fail(code);
}

export function writeU16(target: Uint8Array<ArrayBuffer>, offset: number, value: number): void {
  new DataView(target.buffer).setUint16(offset, value);
}

export function writeU32(target: Uint8Array<ArrayBuffer>, offset: number, value: number): void {
  new DataView(target.buffer).setUint32(offset, value);
}

export function writeU64(target: Uint8Array<ArrayBuffer>, offset: number, value: number): void {
  requireTimestamp(value);
  new DataView(target.buffer).setBigUint64(offset, BigInt(value));
}

export function requireTimestamp(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) fail("invalid_timestamp");
}

export function readU16(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset);
}

export function readU32(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset);
}

export function readU64(bytes: Uint8Array, offset: number): number {
  const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail("invalid_timestamp");
  return Number(value);
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!value.isWellFormed() || !/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    return fail("invalid_base64url");
  }
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  } catch {
    return fail("invalid_base64url");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (encodeBase64Url(bytes) !== value) fail("invalid_base64url");
  return bytes;
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(length);
  for (let offset = 0; offset < output.byteLength; offset += 65_536) {
    crypto.getRandomValues(output.subarray(offset, Math.min(offset + 65_536, output.byteLength)));
  }
  return output;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", owned(bytes)));
}
