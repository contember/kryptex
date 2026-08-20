import {
  ALLOWED_KXE1_LENGTHS,
  ALLOWED_KXR1_LENGTHS,
  type ContentMode,
  type FactorMode
} from "./protocol.js";
import {
  ContractValidationError,
  decodeCanonicalBase64Url,
  expectString
} from "./validation.js";

export interface Kxe1Header {
  readonly bytes: Uint8Array;
  readonly clientNotAfter: number;
  readonly contentMode: ContentMode;
  readonly encoded: string;
  readonly factorMode: FactorMode;
  readonly maxRetrievals: number;
  readonly nonce: Uint8Array;
  readonly schemaDigest: Uint8Array;
}

export interface Kxr1Header {
  readonly bytes: Uint8Array;
  readonly ciphertextLength: number;
  readonly clientNotAfter: number;
  readonly enc: Uint8Array;
  readonly encoded: string;
  readonly schemaDigest: Uint8Array;
}

function expectMagic(bytes: Uint8Array, expected: readonly number[], context: string): void {
  if (expected.some((byte, index) => bytes[index] !== byte)) {
    throw new ContractValidationError(`${context} has invalid magic`);
  }
}

function readSafeTimestamp(view: DataView, offset: number, context: string): number {
  const value = view.getBigUint64(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ContractValidationError(`${context} timestamp exceeds Number.MAX_SAFE_INTEGER`);
  }
  return Number(value);
}

function parseFactorMode(value: number, context: string): FactorMode {
  if (value === 0 || value === 1 || value === 2) {
    return value;
  }
  throw new ContractValidationError(`${context} has an unsupported factor mode`);
}

function parseContentMode(value: number, context: string): ContentMode {
  if (value === 1 || value === 2) {
    return value;
  }
  throw new ContractValidationError(`${context} has an unsupported content mode`);
}

export function parseKxe1Envelope(value: unknown): Kxe1Header {
  const encoded = expectString(value, "KXE1 envelope");
  const bytes = decodeCanonicalBase64Url(encoded, "KXE1 envelope");
  if (!ALLOWED_KXE1_LENGTHS.includes(bytes.byteLength)) {
    throw new ContractValidationError("KXE1 envelope has an unsupported length");
  }

  expectMagic(bytes, [0x4b, 0x58, 0x45, 0x31], "KXE1 envelope");
  if (bytes[4] !== 1) {
    throw new ContractValidationError("KXE1 envelope has an unsupported suite");
  }
  const contentMode = parseContentMode(bytes[5] ?? -1, "KXE1 envelope");
  const factorMode = parseFactorMode(bytes[6] ?? -1, "KXE1 envelope");
  if (bytes[7] !== 0) {
    throw new ContractValidationError("KXE1 envelope has nonzero reserved flags");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const clientNotAfter = readSafeTimestamp(view, 8, "KXE1 envelope");
  const maxRetrievals = view.getUint16(16);
  const schemaDigest = bytes.slice(18, 50);
  const schemaDigestIsZero = schemaDigest.every((byte) => byte === 0);
  if (contentMode === 1) {
    if (maxRetrievals < 1 || maxRetrievals > 10) {
      throw new ContractValidationError("KXE1 send envelope has an invalid retrieval count");
    }
    if (!schemaDigestIsZero) {
      throw new ContractValidationError("KXE1 send envelope has a nonzero schema digest");
    }
  } else if (maxRetrievals !== 0) {
    throw new ContractValidationError("KXE1 schema envelope has a nonzero retrieval count");
  }

  return {
    bytes,
    clientNotAfter,
    contentMode,
    encoded,
    factorMode,
    maxRetrievals,
    nonce: bytes.slice(50, 62),
    schemaDigest
  };
}

export function parseKxr1Envelope(value: unknown): Kxr1Header {
  const encoded = expectString(value, "KXR1 envelope");
  const bytes = decodeCanonicalBase64Url(encoded, "KXR1 envelope");
  if (!ALLOWED_KXR1_LENGTHS.includes(bytes.byteLength)) {
    throw new ContractValidationError("KXR1 envelope has an unsupported length");
  }

  expectMagic(bytes, [0x4b, 0x58, 0x52, 0x31], "KXR1 envelope");
  if (bytes[4] !== 1) {
    throw new ContractValidationError("KXR1 envelope has an unsupported suite");
  }
  if (bytes[5] !== 0 || bytes[6] !== 0 || bytes[7] !== 0) {
    throw new ContractValidationError("KXR1 envelope has nonzero reserved bits");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const clientNotAfter = readSafeTimestamp(view, 8, "KXR1 envelope");
  const encLength = view.getUint16(48);
  if (encLength !== 32) {
    throw new ContractValidationError("KXR1 envelope has an invalid encapsulated-key length");
  }
  const ciphertextLength = view.getUint32(50);
  const allowedCiphertextLengths = ALLOWED_KXR1_LENGTHS.map((length) => length - 86);
  if (!allowedCiphertextLengths.includes(ciphertextLength) || bytes.byteLength !== 86 + ciphertextLength) {
    throw new ContractValidationError("KXR1 envelope has an invalid ciphertext length");
  }

  return {
    bytes,
    ciphertextLength,
    clientNotAfter,
    enc: bytes.slice(54, 86),
    encoded,
    schemaDigest: bytes.slice(16, 48)
  };
}
