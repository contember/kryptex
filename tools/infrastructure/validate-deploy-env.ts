import { parseApiJsonText } from "@kryptex/contracts/api";

const LOCAL_TURNSTILE_DUMMY_SECRET = "1x0000000000000000000000000000000AA";
const LOCAL_TURNSTILE_DUMMY_SITEKEY = "1x00000000000000000000AA";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

function decodeSecret(value: unknown, name: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error(`${name} must be canonical base64url for 32 bytes`);
  }
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=");
  } catch {
    throw new Error(`${name} must be canonical base64url for 32 bytes`);
  }
  const canonical = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  if (binary.length !== 32 || canonical !== value) {
    throw new Error(`${name} must be canonical base64url for 32 bytes`);
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function parseKeyring(text: string, name: string): ReadonlyMap<string, Uint8Array> {
  return parseApiJsonText(text, (value) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`${name} must be a JSON object`);
    }
    const result = new Map<string, Uint8Array>();
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(key)) {
        throw new Error(`${name} contains an invalid key ID`);
      }
      result.set(key, decodeSecret(Reflect.get(value, key), `${name}.${key}`));
    }
    if (result.size === 0) {
      throw new Error(`${name} must contain named keys`);
    }
    return result;
  });
}

function equalBytes(first: Uint8Array, second: Uint8Array): boolean {
  return first.every((value, index) => value === second[index]);
}

interface SelectedKeyring {
  readonly keys: ReadonlyMap<string, Uint8Array>;
  readonly selected: Uint8Array;
}

function selectedKeyring(keyringName: string, activeIdName: string): SelectedKeyring {
  const activeId = requiredEnvironment(activeIdName);
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(activeId)) {
    throw new Error(`${activeIdName} is invalid`);
  }
  const keys = parseKeyring(requiredEnvironment(keyringName), keyringName);
  const selected = keys.get(activeId);
  if (selected === undefined) {
    throw new Error(`${activeIdName} is absent from ${keyringName}`);
  }
  return { keys, selected };
}

function assertIndependentKeys(capabilityKeys: ReadonlyMap<string, Uint8Array>, permitKeys: ReadonlyMap<string, Uint8Array>, rateLimitKey: Uint8Array): void {
  for (const capabilityKey of capabilityKeys.values()) {
    if (equalBytes(capabilityKey, rateLimitKey)) {
      throw new Error("Capability, permit-issuance, and rate-limit keys must be independent");
    }
    for (const permitKey of permitKeys.values()) {
      if (equalBytes(capabilityKey, permitKey)) {
        throw new Error("Capability, permit-issuance, and rate-limit keys must be independent");
      }
    }
  }
  for (const permitKey of permitKeys.values()) {
    if (equalBytes(permitKey, rateLimitKey)) {
      throw new Error("Capability, permit-issuance, and rate-limit keys must be independent");
    }
  }
}

function validate(): void {
  const originText = requiredEnvironment("KRYPTEX_ORIGIN");
  let origin: URL;
  try {
    origin = new URL(originText);
  } catch {
    throw new Error("KRYPTEX_ORIGIN must be an exact HTTPS origin");
  }
  if (origin.protocol !== "https:" || origin.origin !== originText) {
    throw new Error("KRYPTEX_ORIGIN must be an exact HTTPS origin");
  }
  if (requiredEnvironment("TURNSTILE_EXPECTED_HOSTNAME") !== origin.hostname) {
    throw new Error("TURNSTILE_EXPECTED_HOSTNAME must match KRYPTEX_ORIGIN");
  }
  if (requiredEnvironment("TURNSTILE_EXPECTED_ACTION") !== "create_permit") {
    throw new Error("TURNSTILE_EXPECTED_ACTION must be create_permit");
  }

  const sitekey = requiredEnvironment("VITE_TURNSTILE_SITE_KEY");
  const turnstileSecret = requiredEnvironment("TURNSTILE_SECRET_KEY");
  if (sitekey === LOCAL_TURNSTILE_DUMMY_SITEKEY || turnstileSecret === LOCAL_TURNSTILE_DUMMY_SECRET) {
    throw new Error("Production must not use Cloudflare Turnstile dummy credentials");
  }
  if (sitekey.length > 2048 || turnstileSecret.length > 2048) {
    throw new Error("Turnstile credentials have an invalid length");
  }

  const capabilityKeyring = selectedKeyring("CAPABILITY_HMAC_KEYRING", "CAPABILITY_ACTIVE_KEY_ID");
  const permitKeyring = selectedKeyring("PERMIT_ISSUANCE_KEYRING", "PERMIT_ISSUANCE_ACTIVE_KEY_ID");
  const rateLimitKey = decodeSecret(requiredEnvironment("RATE_LIMIT_KEY"), "RATE_LIMIT_KEY");
  assertIndependentKeys(capabilityKeyring.keys, permitKeyring.keys, rateLimitKey);
}

try {
  validate();
  console.log("Validated production deployment variables and secrets");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Production deployment environment is invalid");
  process.exitCode = 1;
}
