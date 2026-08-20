import { ContractValidationError } from "./validation.js";

class JsonScanner {
  private index = 0;

  constructor(private readonly source: string) {}

  scan(): void {
    this.skipWhitespace();
    this.scanValue();
    this.skipWhitespace();
    if (this.index !== this.source.length) {
      throw new ContractValidationError("JSON contains trailing input");
    }
  }

  private scanValue(): void {
    const character = this.source[this.index];
    if (character === "{") {
      this.scanObject();
      return;
    }
    if (character === "[") {
      this.scanArray();
      return;
    }
    if (character === '"') {
      this.scanString();
      return;
    }
    if (character === "t") {
      this.scanLiteral("true");
      return;
    }
    if (character === "f") {
      this.scanLiteral("false");
      return;
    }
    if (character === "n") {
      this.scanLiteral("null");
      return;
    }
    this.scanNumber();
  }

  private scanObject(): void {
    this.index += 1;
    this.skipWhitespace();
    const keys = new Set<string>();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return;
    }
    while (this.index < this.source.length) {
      const key = this.scanString();
      if (keys.has(key)) {
        throw new ContractValidationError("JSON contains a duplicate object key");
      }
      keys.add(key);
      this.skipWhitespace();
      this.expectCharacter(":");
      this.skipWhitespace();
      this.scanValue();
      this.skipWhitespace();
      const separator = this.source[this.index];
      if (separator === "}") {
        this.index += 1;
        return;
      }
      this.expectCharacter(",");
      this.skipWhitespace();
    }
    throw new ContractValidationError("JSON object is incomplete");
  }

  private scanArray(): void {
    this.index += 1;
    this.skipWhitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return;
    }
    while (this.index < this.source.length) {
      this.scanValue();
      this.skipWhitespace();
      const separator = this.source[this.index];
      if (separator === "]") {
        this.index += 1;
        return;
      }
      this.expectCharacter(",");
      this.skipWhitespace();
    }
    throw new ContractValidationError("JSON array is incomplete");
  }

  private scanString(): string {
    const start = this.index;
    this.expectCharacter('"');
    while (this.index < this.source.length) {
      const character = this.source[this.index];
      if (character === '"') {
        this.index += 1;
        const decoded: unknown = JSON.parse(this.source.slice(start, this.index));
        if (typeof decoded !== "string") {
          throw new ContractValidationError("JSON string is invalid");
        }
        return decoded;
      }
      if (character === "\\") {
        this.index += 1;
        const escape = this.source[this.index];
        if (escape === "u") {
          const hex = this.source.slice(this.index + 1, this.index + 5);
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) {
            throw new ContractValidationError("JSON Unicode escape is invalid");
          }
          this.index += 5;
          continue;
        }
        if (escape === '"' || escape === "\\" || escape === "/" || escape === "b" || escape === "f" || escape === "n" || escape === "r" || escape === "t") {
          this.index += 1;
          continue;
        }
        throw new ContractValidationError("JSON escape is invalid");
      }
      if (character === undefined || character.charCodeAt(0) < 0x20) {
        throw new ContractValidationError("JSON string is invalid");
      }
      this.index += 1;
    }
    throw new ContractValidationError("JSON string is incomplete");
  }

  private scanLiteral(literal: string): void {
    if (this.source.slice(this.index, this.index + literal.length) !== literal) {
      throw new ContractValidationError("JSON literal is invalid");
    }
    this.index += literal.length;
  }

  private scanNumber(): void {
    const remaining = this.source.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(remaining);
    if (match === null || match[0].length === 0) {
      throw new ContractValidationError("JSON value is invalid");
    }
    this.index += match[0].length;
  }

  private skipWhitespace(): void {
    while (/^[\t\n\r ]$/u.test(this.source[this.index] ?? "")) {
      this.index += 1;
    }
  }

  private expectCharacter(expected: string): void {
    if (this.source[this.index] !== expected) {
      throw new ContractValidationError(`JSON expected ${expected}`);
    }
    this.index += 1;
  }
}

export function parseJsonWithoutDuplicateKeys(text: string): unknown {
  new JsonScanner(text).scan();
  try {
    const parsed: unknown = JSON.parse(text);
    return parsed;
  } catch {
    throw new ContractValidationError("JSON is invalid");
  }
}

