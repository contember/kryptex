import setupArgon2id from "argon2id/lib/setup.js";
import initArgon2idNoSimd from "argon2id/dist/no-simd.wasm?init";
import initArgon2idSimd from "argon2id/dist/simd.wasm?init";
import type { FactorMode } from "@kryptex/contracts/protocol";
import { requireLength, utf8 } from "./bytes.js";
import { fail, opaqueFailure } from "./errors.js";

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const zeroFactor = new Uint8Array(32);

function wasmInitializer(value: unknown): (imports: WebAssembly.Imports) => Promise<WebAssembly.Instance> {
  if (typeof value !== "function") fail("factor_derivation_failed");
  return async (imports) => {
    const result: unknown = await Reflect.apply(value, undefined, [imports]);
    if (!(result instanceof WebAssembly.Instance)) fail("factor_derivation_failed");
    return result;
  };
}

async function instantiateArgon2(
  initialize: (imports: WebAssembly.Imports) => Promise<WebAssembly.Instance>,
  imports: WebAssembly.Imports
): Promise<WebAssembly.WebAssemblyInstantiatedSource> {
  const instance = await initialize(imports);
  const module = await WebAssembly.compile(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
  return { instance, module };
}

export function encodeRandomFactor(bytes: Uint8Array): string {
  requireLength(bytes, 32, "invalid_random_factor");
  let accumulator = 0;
  let bitCount = 0;
  let compact = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      compact += alphabet[(accumulator >>> bitCount) & 31] ?? "";
      accumulator &= (1 << bitCount) - 1;
    }
  }
  if (bitCount > 0) compact += alphabet[(accumulator << (5 - bitCount)) & 31] ?? "";
  return `${compact.slice(0, 13)}-${compact.slice(13, 26)}-${compact.slice(26, 39)}-${compact.slice(39)}`;
}

export function decodeRandomFactor(value: string): Uint8Array<ArrayBuffer> {
  if (!value.isWellFormed() || /\s/u.test(value)) fail("invalid_random_factor");
  let compact = "";
  let lastHyphen = false;
  for (const character of value.toUpperCase()) {
    if (character === "-") {
      if (lastHyphen || ![13, 26, 39].includes(compact.length)) fail("invalid_random_factor");
      lastHyphen = true;
      continue;
    }
    compact += character;
    lastHyphen = false;
  }
  if (lastHyphen) fail("invalid_random_factor");
  compact = compact.replaceAll("O", "0").replaceAll("I", "1").replaceAll("L", "1");
  if (compact.length !== 52 || /[^0-9A-HJKMNP-TV-Z]/u.test(compact) || compact.includes("U")) {
    fail("invalid_random_factor");
  }
  const output: number[] = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const character of compact) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) fail("invalid_random_factor");
    accumulator = (accumulator << 5) | digit;
    bitCount += 5;
    while (bitCount >= 8) {
      bitCount -= 8;
      output.push((accumulator >>> bitCount) & 0xff);
      accumulator &= (1 << bitCount) - 1;
    }
  }
  if (bitCount !== 4 || accumulator !== 0 || output.length !== 32) fail("invalid_random_factor");
  return Uint8Array.from(output);
}

export function validatePassphrase(passphrase: string): Uint8Array<ArrayBuffer> {
  const bytes = utf8(passphrase);
  if (bytes.byteLength < 12 || bytes.byteLength > 256) fail("invalid_passphrase");
  return bytes;
}

export async function derivePassphraseFactor(passphrase: string, salt: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  requireLength(salt, 16, "invalid_salt");
  const password = validatePassphrase(passphrase);
  try {
    return await opaqueFailure(async () => {
      // Per-call setup avoids retaining 65 MiB of WASM memory; JavaScript cannot control when GC releases it.
      const argon2id = await setupArgon2id(
        (imports) => instantiateArgon2(wasmInitializer(initArgon2idSimd), imports),
        (imports) => instantiateArgon2(wasmInitializer(initArgon2idNoSimd), imports)
      );
      const derived = argon2id({
        memorySize: 65536,
        parallelism: 1,
        passes: 3,
        password,
        salt: new Uint8Array(salt),
        tagLength: 32
      });
      try {
        return new Uint8Array(derived);
      } finally {
        derived.fill(0);
      }
    }, "factor_derivation_failed");
  } finally {
    password.fill(0);
  }
}

export async function deriveConfirmedPassphraseFactor(
  passphrase: string,
  confirmation: string,
  salt: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  if (passphrase !== confirmation) fail("passphrase_mismatch");
  return derivePassphraseFactor(passphrase, salt);
}

export function factorForMode(mode: FactorMode, factor?: Uint8Array): Uint8Array<ArrayBuffer> {
  if (mode === 0) return new Uint8Array(zeroFactor);
  if (factor === undefined) fail("factor_required");
  requireLength(factor, 32, "invalid_factor");
  return new Uint8Array(factor);
}
