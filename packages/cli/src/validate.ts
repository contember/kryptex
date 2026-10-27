// Strict structural checks for JSON the CLI reads back: form specs and its own state records.

export class ShapeError extends Error {
  constructor(context: string) {
    super(`${context} is invalid`);
    this.name = "ShapeError";
  }
}

export function exactObject(value: unknown, keys: readonly string[], context: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ShapeError(context);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ShapeError(context);
  }
  const output: Record<string, unknown> = {};
  for (const key of keys) {
    output[key] = Reflect.get(value, key);
  }
  return output;
}

export function field(object: Readonly<Record<string, unknown>>, key: string): unknown {
  return object[key];
}

export function stringValue(value: unknown, context: string): string {
  if (typeof value !== "string") {
    throw new ShapeError(context);
  }
  return value;
}

export function booleanValue(value: unknown, context: string): boolean {
  if (typeof value !== "boolean") {
    throw new ShapeError(context);
  }
  return value;
}

export function integerValue(value: unknown, context: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ShapeError(context);
  }
  return value;
}

export function arrayValue(value: unknown, context: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new ShapeError(context);
  }
  return value;
}

export function literal<const T extends string>(value: unknown, allowed: readonly T[], context: string): T {
  const match = allowed.find((candidate) => candidate === value);
  if (match === undefined) {
    throw new ShapeError(context);
  }
  return match;
}

export function base64UrlValue(value: unknown, byteLength: number, context: string): string {
  const text = stringValue(value, context);
  if (!/^[A-Za-z0-9_-]*$/u.test(text) || text.length !== Math.ceil((byteLength * 8) / 6)) {
    throw new ShapeError(context);
  }
  return text;
}

export function nullable<T>(value: unknown, parse: (value: unknown) => T): T | null {
  return value === null ? null : parse(value);
}

export function base64UrlText(value: unknown, context: string): string {
  const text = stringValue(value, context);
  if (!/^[A-Za-z0-9_-]+$/u.test(text)) {
    throw new ShapeError(context);
  }
  return text;
}
