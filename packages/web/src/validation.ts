const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CANONICAL_FACTOR_PATTERN = /^(?:[0-9A-HJKMNP-TV-Z]{13}-){3}[0-9A-HJKMNP-TV-Z]{13}$/i;
const UNGROUPED_FACTOR_PATTERN = /^[0-9A-HJKMNP-TV-Z]{52}$/i;

export interface PassphraseValidation {
  readonly byteLength: number;
  readonly valid: boolean;
  readonly message: string;
}

export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

export function validatePassphrase(value: string, confirmation: string): PassphraseValidation {
  const byteLength = utf8ByteLength(value);
  if (byteLength < 12) {
    return { byteLength, message: "Use at least 12 UTF-8 bytes.", valid: false };
  }
  if (byteLength > 256) {
    return { byteLength, message: "Use at most 256 UTF-8 bytes.", valid: false };
  }
  if (value !== confirmation) {
    return { byteLength, message: "The confirmation must match exactly.", valid: false };
  }
  return { byteLength, message: `${byteLength} UTF-8 bytes · exact match`, valid: true };
}

export function normalizeCrockfordFactor(value: string): string | null {
  const mapped = value.toUpperCase().replaceAll("O", "0").replaceAll("I", "1").replaceAll("L", "1");
  const validShape = mapped.includes("-")
    ? CANONICAL_FACTOR_PATTERN.test(mapped)
    : UNGROUPED_FACTOR_PATTERN.test(mapped);
  if (!validShape || /[U\s]/i.test(value)) return null;

  const compact = mapped.replaceAll("-", "");
  if (compact.length !== 52) return null;
  const lastValue = CROCKFORD_ALPHABET.indexOf(compact.charAt(51));
  if (lastValue !== 0 && lastValue !== 16) return null;

  return `${compact.slice(0, 13)}-${compact.slice(13, 26)}-${compact.slice(26, 39)}-${compact.slice(39)}`;
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
