export class ContractValidationError extends Error {
  readonly code = "invalid_contract";

  constructor(message: string) {
    super(message);
    this.name = "ContractValidationError";
  }
}

export function expectExactObject(value: unknown, expectedKeys: readonly string[], context: string): object {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ContractValidationError(`${context} must be an object`);
  }

  const actualKeys = Reflect.ownKeys(value);
  if (actualKeys.some((key) => typeof key !== "string")) {
    throw new ContractValidationError(`${context} has unsupported keys`);
  }

  const sortedActual = actualKeys.map(String).sort();
  const sortedExpected = [...expectedKeys].sort();
  if (
    sortedActual.length !== sortedExpected.length ||
    sortedActual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new ContractValidationError(`${context} has unexpected or missing keys`);
  }

  return value;
}

export function readProperty(value: object, key: string, context: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
    throw new ContractValidationError(`${context}.${key} must be an enumerable data property`);
  }
  return descriptor.value;
}

export function expectString(value: unknown, context: string): string {
  if (typeof value !== "string" || !value.isWellFormed()) {
    throw new ContractValidationError(`${context} must be a string`);
  }
  return value;
}

export function expectBoolean(value: unknown, context: string): boolean {
  if (typeof value !== "boolean") {
    throw new ContractValidationError(`${context} must be a boolean`);
  }
  return value;
}

export function expectSafeInteger(value: unknown, context: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ContractValidationError(`${context} must be an unsigned safe integer`);
  }
  return value;
}

export function expectIntegerInRange(value: unknown, minimum: number, maximum: number, context: string): number {
  const integer = expectSafeInteger(value, context);
  if (integer < minimum || integer > maximum) {
    throw new ContractValidationError(`${context} is outside the allowed range`);
  }
  return integer;
}

export function expectArray(value: unknown, minimum: number, maximum: number, context: string): readonly unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new ContractValidationError(`${context} must contain ${minimum} through ${maximum} items`);
  }
  return value;
}

export function expectUtf8Length(
  value: unknown,
  minimum: number,
  maximum: number,
  context: string
): string {
  const text = expectString(value, context);
  const length = new TextEncoder().encode(text).byteLength;
  if (length < minimum || length > maximum) {
    throw new ContractValidationError(`${context} has an invalid UTF-8 byte length`);
  }
  return text;
}

export function decodeCanonicalBase64Url(value: unknown, context: string): Uint8Array {
  const encoded = expectString(value, context);
  if (!/^[A-Za-z0-9_-]*$/.test(encoded) || encoded.length % 4 === 1) {
    throw new ContractValidationError(`${context} is not canonical base64url`);
  }

  const paddingLength = (4 - (encoded.length % 4)) % 4;
  const base64 = encoded.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(paddingLength);
  let binary: string;
  try {
    binary = atob(base64);
  } catch {
    throw new ContractValidationError(`${context} is not canonical base64url`);
  }

  const canonical = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  if (canonical !== encoded) {
    throw new ContractValidationError(`${context} is not canonical base64url`);
  }

  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function expectCanonicalBase64UrlLength(
  value: unknown,
  byteLength: number,
  context: string
): string {
  const encoded = expectString(value, context);
  const decoded = decodeCanonicalBase64Url(encoded, context);
  if (decoded.byteLength !== byteLength) {
    throw new ContractValidationError(`${context} must decode to ${byteLength} bytes`);
  }
  return encoded;
}

export function expectCanonicalBase64UrlAllowedLengths(
  value: unknown,
  allowedByteLengths: readonly number[],
  context: string
): string {
  const encoded = expectString(value, context);
  const decoded = decodeCanonicalBase64Url(encoded, context);
  if (!allowedByteLengths.includes(decoded.byteLength)) {
    throw new ContractValidationError(`${context} has an unsupported decoded length`);
  }
  return encoded;
}
