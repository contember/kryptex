import type { BundleKind, FactorMode } from "@kryptex/contracts/protocol";
import { decodeBase64Url, encodeBase64Url, readU16, readU64, requireLength, writeU16, writeU64 } from "./bytes.js";
import { fail } from "./errors.js";

export interface SendRecipientBundle {
  readonly factorMode: FactorMode;
  readonly kind: 1;
  readonly salt: Uint8Array<ArrayBuffer>;
  readonly sendSeed: Uint8Array<ArrayBuffer>;
  readonly serverExpiresAt: number;
}

export interface SendManagementBundle {
  readonly kind: 2;
  readonly locator: Uint8Array<ArrayBuffer>;
  readonly manageSeed: Uint8Array<ArrayBuffer>;
  readonly serverExpiresAt: number;
}

export interface RequestWriteBundle {
  readonly factorMode: FactorMode;
  readonly kind: 3;
  readonly recipientPublicKey: Uint8Array<ArrayBuffer>;
  readonly requestLocator: Uint8Array<ArrayBuffer>;
  readonly salt: Uint8Array<ArrayBuffer>;
  readonly serverExpiresAt: number;
  readonly writeSeed: Uint8Array<ArrayBuffer>;
}

export interface RequestPickupBundle {
  readonly kind: 4;
  readonly ownerSeed: Uint8Array<ArrayBuffer>;
  readonly requestLocator: Uint8Array<ArrayBuffer>;
  readonly serverExpiresAt: number;
}

export type KryptexBundle = SendRecipientBundle | SendManagementBundle | RequestWriteBundle | RequestPickupBundle;

function factorMode(value: number): FactorMode {
  if (value === 0 || value === 1 || value === 2) return value;
  return fail("invalid_bundle");
}

function validateSalt(mode: FactorMode, salt: Uint8Array): void {
  requireLength(salt, 16, "invalid_bundle");
  if (mode !== 1 && salt.some((byte) => byte !== 0)) fail("invalid_bundle");
}

function bodyLength(kind: BundleKind): number {
  if (kind === 1) return 57;
  if (kind === 2) return 56;
  if (kind === 3) return 105;
  return 56;
}

function header(kind: BundleKind): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(8 + bodyLength(kind));
  output.set([0x4b, 0x58, 0x42, 0x31, kind, 1], 0);
  writeU16(output, 6, bodyLength(kind));
  return output;
}

export function encodeBundle(bundle: KryptexBundle): string {
  const output = header(bundle.kind);
  if (bundle.kind === 1) {
    requireLength(bundle.sendSeed, 32, "invalid_bundle");
    validateSalt(bundle.factorMode, bundle.salt);
    output.set(bundle.sendSeed, 8);
    output[40] = bundle.factorMode;
    output.set(bundle.salt, 41);
    writeU64(output, 57, bundle.serverExpiresAt);
  } else if (bundle.kind === 2) {
    requireLength(bundle.locator, 16, "invalid_bundle");
    requireLength(bundle.manageSeed, 32, "invalid_bundle");
    output.set(bundle.locator, 8);
    output.set(bundle.manageSeed, 24);
    writeU64(output, 56, bundle.serverExpiresAt);
  } else if (bundle.kind === 3) {
    requireLength(bundle.requestLocator, 16, "invalid_bundle");
    requireLength(bundle.writeSeed, 32, "invalid_bundle");
    requireLength(bundle.recipientPublicKey, 32, "invalid_bundle");
    validateSalt(bundle.factorMode, bundle.salt);
    output.set(bundle.requestLocator, 8);
    output.set(bundle.writeSeed, 24);
    output[56] = bundle.factorMode;
    output.set(bundle.salt, 57);
    output.set(bundle.recipientPublicKey, 73);
    writeU64(output, 105, bundle.serverExpiresAt);
  } else {
    requireLength(bundle.requestLocator, 16, "invalid_bundle");
    requireLength(bundle.ownerSeed, 32, "invalid_bundle");
    output.set(bundle.requestLocator, 8);
    output.set(bundle.ownerSeed, 24);
    writeU64(output, 56, bundle.serverExpiresAt);
  }
  return encodeBase64Url(output);
}

export function decodeBundle(encoded: string): KryptexBundle {
  const bytes = decodeBase64Url(encoded);
  if (bytes.byteLength < 8 || bytes[0] !== 0x4b || bytes[1] !== 0x58 || bytes[2] !== 0x42 || bytes[3] !== 0x31) {
    return fail("invalid_bundle");
  }
  if (bytes[5] !== 1) fail("invalid_bundle");
  const rawKind = bytes[4];
  if (rawKind !== 1 && rawKind !== 2 && rawKind !== 3 && rawKind !== 4) fail("invalid_bundle");
  const expectedBodyLength = bodyLength(rawKind);
  if (readU16(bytes, 6) !== expectedBodyLength || bytes.byteLength !== expectedBodyLength + 8) fail("invalid_bundle");
  if (rawKind === 1) {
    const mode = factorMode(bytes[40] ?? -1);
    const salt = bytes.slice(41, 57);
    validateSalt(mode, salt);
    return { factorMode: mode, kind: 1, salt, sendSeed: bytes.slice(8, 40), serverExpiresAt: readU64(bytes, 57) };
  }
  if (rawKind === 2) {
    return { kind: 2, locator: bytes.slice(8, 24), manageSeed: bytes.slice(24, 56), serverExpiresAt: readU64(bytes, 56) };
  }
  if (rawKind === 3) {
    const mode = factorMode(bytes[56] ?? -1);
    const salt = bytes.slice(57, 73);
    validateSalt(mode, salt);
    return {
      factorMode: mode,
      kind: 3,
      recipientPublicKey: bytes.slice(73, 105),
      requestLocator: bytes.slice(8, 24),
      salt,
      serverExpiresAt: readU64(bytes, 105),
      writeSeed: bytes.slice(24, 56)
    };
  }
  return { kind: 4, ownerSeed: bytes.slice(24, 56), requestLocator: bytes.slice(8, 24), serverExpiresAt: readU64(bytes, 56) };
}
