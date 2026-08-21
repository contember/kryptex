import type { RequestSchemaField, SendField } from "@kryptex/contracts/payloads";
import { MAX_FIELDS, MAX_HELP_UTF8_BYTES, MAX_LABEL_UTF8_BYTES, MAX_VALUE_UTF8_BYTES } from "@kryptex/contracts/protocol";

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CANONICAL_FACTOR_PATTERN = /^(?:[0-9A-HJKMNP-TV-Z]{5}-){4}[0-9A-HJKMNP-TV-Z]{6}$/i;
const UNGROUPED_FACTOR_PATTERN = /^[0-9A-HJKMNP-TV-Z]{26}$/i;

export type PassphraseStrength = "short" | "weak" | "fair";

export interface PassphraseValidation {
  readonly byteLength: number;
  readonly strength: PassphraseStrength;
  readonly valid: boolean;
  readonly message: string;
}

export interface DraftValidation {
  readonly message: string;
  readonly valid: boolean;
}

export interface RequestDraftField {
  readonly help: string;
  readonly label: string;
}

export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function validDraft(message: string): DraftValidation {
  return { message, valid: true };
}

function invalidDraft(message: string): DraftValidation {
  return { message, valid: false };
}

export function validateSendDraft(mode: "text" | "fields", text: string, fields: readonly SendField[]): DraftValidation {
  if (mode === "text") {
    const bytes = utf8ByteLength(text);
    if (bytes < 1) return invalidDraft("Enter a secret.");
    if (bytes > MAX_VALUE_UTF8_BYTES) return invalidDraft(`Secret text must be at most ${MAX_VALUE_UTF8_BYTES} UTF-8 bytes.`);
    return validDraft(`${bytes} UTF-8 bytes`);
  }
  if (fields.length < 1 || fields.length > MAX_FIELDS) return invalidDraft(`Use 1 through ${MAX_FIELDS} fields.`);
  for (const field of fields) {
    const labelBytes = utf8ByteLength(field.label);
    const valueBytes = utf8ByteLength(field.value);
    if (labelBytes < 1) return invalidDraft("Every field needs a label.");
    if (labelBytes > MAX_LABEL_UTF8_BYTES) return invalidDraft(`Field labels must be at most ${MAX_LABEL_UTF8_BYTES} UTF-8 bytes.`);
    if (valueBytes < 1) return invalidDraft("Every field needs a value.");
    if (valueBytes > MAX_VALUE_UTF8_BYTES) return invalidDraft(`Field values must be at most ${MAX_VALUE_UTF8_BYTES} UTF-8 bytes.`);
  }
  return validDraft(`${fields.length} fields ready`);
}

export function validateRequestDraft(title: string, instructions: string, fields: readonly RequestDraftField[]): DraftValidation {
  const titleBytes = utf8ByteLength(title);
  const instructionBytes = utf8ByteLength(instructions);
  const encodedFields = fields.length + (instructions.length > 0 ? 1 : 0);
  if (titleBytes < 1) return invalidDraft("Enter a request title.");
  if (titleBytes > MAX_LABEL_UTF8_BYTES) return invalidDraft(`The request title must be at most ${MAX_LABEL_UTF8_BYTES} UTF-8 bytes.`);
  if (instructionBytes > MAX_HELP_UTF8_BYTES) return invalidDraft(`Instructions must be at most ${MAX_HELP_UTF8_BYTES} UTF-8 bytes.`);
  if (encodedFields < 1 || encodedFields > MAX_FIELDS) return invalidDraft(`The request can encode at most ${MAX_FIELDS} items including instructions.`);
  for (const field of fields) {
    const labelBytes = utf8ByteLength(field.label);
    const helpBytes = utf8ByteLength(field.help);
    if (labelBytes < 1) return invalidDraft("Every requested item needs a label.");
    if (labelBytes > MAX_LABEL_UTF8_BYTES) return invalidDraft(`Item labels must be at most ${MAX_LABEL_UTF8_BYTES} UTF-8 bytes.`);
    if (helpBytes > MAX_HELP_UTF8_BYTES) return invalidDraft(`Item help must be at most ${MAX_HELP_UTF8_BYTES} UTF-8 bytes.`);
  }
  return validDraft(`${encodedFields} schema items ready`);
}

export function validateRequestAnswers(fields: readonly RequestSchemaField[], answers: Readonly<Record<string, string>>): DraftValidation {
  for (const field of fields) {
    if (field.type === "instruction") continue;
    const value = answers[field.id] ?? "";
    if (field.required && value.length === 0) return invalidDraft(`Answer “${field.label}” before submitting.`);
    if (utf8ByteLength(value) > MAX_VALUE_UTF8_BYTES) return invalidDraft(`Answer “${field.label}” must be at most ${MAX_VALUE_UTF8_BYTES} UTF-8 bytes.`);
  }
  return validDraft("Answers fit the encrypted response limits.");
}

/**
 * Eight bytes is the floor rather than a recommendation: link-only protection is the
 * alternative, and a short passphrase behind Argon2id beats no second secret at all.
 */
export function validatePassphrase(value: string, confirmation: string): PassphraseValidation {
  const byteLength = utf8ByteLength(value);
  if (byteLength < 8) {
    return { byteLength, message: "Use at least 8 UTF-8 bytes.", strength: "short", valid: false };
  }
  const strength = byteLength < 12 ? "weak" : "fair";
  if (byteLength > 256) {
    return { byteLength, message: "Use at most 256 UTF-8 bytes.", strength, valid: false };
  }
  if (value !== confirmation) {
    return { byteLength, message: "The confirmation must match exactly.", strength, valid: false };
  }
  if (strength === "weak") {
    return { byteLength, message: "Short passphrases can be guessed by whoever holds the link. Twelve bytes or more is meaningfully harder.", strength, valid: true };
  }
  return { byteLength, message: `${byteLength} UTF-8 bytes · exact match`, strength, valid: true };
}

export function normalizeCrockfordFactor(value: string): string | null {
  const mapped = value.toUpperCase().replaceAll("O", "0").replaceAll("I", "1").replaceAll("L", "1");
  const validShape = mapped.includes("-")
    ? CANONICAL_FACTOR_PATTERN.test(mapped)
    : UNGROUPED_FACTOR_PATTERN.test(mapped);
  if (!validShape || /[U\s]/i.test(value)) return null;

  const compact = mapped.replaceAll("-", "");
  if (compact.length !== 26) return null;
  const lastValue = CROCKFORD_ALPHABET.indexOf(compact.charAt(25));
  // The final character carries two padding bits, which must be zero.
  if (lastValue < 0 || lastValue % 4 !== 0) return null;

  return `${compact.slice(0, 5)}-${compact.slice(5, 10)}-${compact.slice(10, 15)}-${compact.slice(15, 20)}-${compact.slice(20)}`;
}

export function isValidCrockfordFactor(value: string): boolean {
  return normalizeCrockfordFactor(value) !== null;
}

export function requiredReceiptSaved(
  primarySaved: boolean,
  protection: "second-key" | "link-only" | "passphrase",
  secondKeySaved: boolean,
  privateLinkSaved = true
): boolean {
  return primarySaved && privateLinkSaved && (protection !== "second-key" || secondKeySaved);
}

export function requiredArtifactsWording(count: 1 | 2 | 3): string {
  if (count === 1) return "the required part";
  if (count === 2) return "both required parts";
  return "all three required parts";
}
