export class InternalValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InternalValidationError";
  }
}

export function exactObject(value: unknown, keys: readonly string[], context: string): object {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InternalValidationError(`${context} must be an object`);
  }
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string")) {
    throw new InternalValidationError(`${context} has unsupported keys`);
  }
  const expected = [...keys].sort();
  const sorted = actual.map(String).sort();
  if (expected.length !== sorted.length || expected.some((key, index) => key !== sorted[index])) {
    throw new InternalValidationError(`${context} has unexpected keys`);
  }
  return value;
}

export function property(object: object, key: string, context: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
    throw new InternalValidationError(`${context}.${key} is invalid`);
  }
  return descriptor.value;
}

export function stringProperty(object: object, key: string, context: string): string {
  const value = property(object, key, context);
  if (typeof value !== "string" || !value.isWellFormed()) {
    throw new InternalValidationError(`${context}.${key} must be a string`);
  }
  return value;
}

export function integerProperty(object: object, key: string, context: string): number {
  const value = property(object, key, context);
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new InternalValidationError(`${context}.${key} must be an unsigned integer`);
  }
  return value;
}

export function decodeCanonicalBase64Url(value: string, length: number, context: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new InternalValidationError(`${context} is not canonical base64url`);
  }
  const padding = (4 - (value.length % 4)) % 4;
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(padding));
  } catch {
    throw new InternalValidationError(`${context} is not canonical base64url`);
  }
  const canonical = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  if (canonical !== value || binary.length !== length) {
    throw new InternalValidationError(`${context} has an invalid length or encoding`);
  }
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function parseJson(text: string): unknown {
  return JSON.parse(text, (key: string, value: unknown) => {
    if (key === "__proto__" || key === "constructor") {
      throw new InternalValidationError("unsupported JSON key");
    }
    return value;
  });
}
