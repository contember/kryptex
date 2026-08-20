import { parseApiJsonText } from "@kryptex/contracts/api";

export interface WorkerSecurityEnvironment {
  readonly CAPABILITY_ACTIVE_KEY_ID: string;
  readonly CAPABILITY_HMAC_KEYRING: string;
  readonly EXPECTED_ORIGIN: string;
  readonly PERMIT_ISSUANCE_KEY: string;
  readonly RATE_LIMIT_KEY: string;
  readonly TURNSTILE_EXPECTED_ACTION: string;
  readonly TURNSTILE_EXPECTED_HOSTNAME: string;
  readonly TURNSTILE_SECRET_KEY: string;
}

export interface WorkerEnv extends WorkerSecurityEnvironment {
  readonly ASSETS: Fetcher;
  readonly CIPHERTEXT: R2Bucket;
  readonly CREATE_PERMIT_OBJECTS: DurableObjectNamespace;
  readonly REQUEST_OBJECTS: DurableObjectNamespace;
  readonly SEND_OBJECTS: DurableObjectNamespace;
}

export interface CheckedWorkerEnvironment {
  readonly activeCapabilityKey: Uint8Array;
  readonly activeCapabilityKeyId: string;
  readonly capabilityKeys: ReadonlyMap<string, Uint8Array>;
  readonly expectedOrigin: string;
  readonly permitIssuanceKey: Uint8Array;
  readonly rateLimitKey: Uint8Array;
  readonly turnstileAction: "create_permit";
  readonly turnstileHostname: string;
  readonly turnstileSecretKey: string;
}

function decodeSecret(value: unknown, name: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error(`${name} must be canonical base64url for 32 bytes`);
  }
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/") + "=";
  let binary: string;
  try {
    binary = atob(base64);
  } catch {
    throw new Error(`${name} must be canonical base64url for 32 bytes`);
  }
  const canonical = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  if (canonical !== value || binary.length !== 32) {
    throw new Error(`${name} must be canonical base64url for 32 bytes`);
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function parseCapabilityKeyring(text: string): ReadonlyMap<string, Uint8Array> {
  return parseApiJsonText(text, (value) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error("CAPABILITY_HMAC_KEYRING must be a JSON object");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length === 0 || keys.some((key) => typeof key !== "string")) {
      throw new Error("CAPABILITY_HMAC_KEYRING must contain named keys");
    }
    const result = new Map<string, Uint8Array>();
    for (const key of keys) {
      if (typeof key !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(key)) {
        throw new Error("CAPABILITY_HMAC_KEYRING contains an invalid key ID");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error("CAPABILITY_HMAC_KEYRING contains an invalid property");
      }
      result.set(key, decodeSecret(descriptor.value, `CAPABILITY_HMAC_KEYRING.${key}`));
    }
    return result;
  });
}

export function checkWorkerEnvironment(env: WorkerSecurityEnvironment): CheckedWorkerEnvironment {
  let expectedOrigin: string;
  try {
    const url = new URL(env.EXPECTED_ORIGIN);
    if ((url.protocol !== "https:" && url.protocol !== "http:") || url.origin !== env.EXPECTED_ORIGIN) {
      throw new Error("invalid origin");
    }
    expectedOrigin = url.origin;
  } catch {
    throw new Error("EXPECTED_ORIGIN must be an exact HTTP origin");
  }
  if (!/^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*)$/u.test(env.TURNSTILE_EXPECTED_HOSTNAME)) {
    throw new Error("TURNSTILE_EXPECTED_HOSTNAME is invalid");
  }
  if (env.TURNSTILE_EXPECTED_ACTION !== "create_permit") {
    throw new Error("TURNSTILE_EXPECTED_ACTION must be create_permit");
  }
  if (env.TURNSTILE_SECRET_KEY.length < 1 || env.TURNSTILE_SECRET_KEY.length > 2048) {
    throw new Error("TURNSTILE_SECRET_KEY has an invalid length");
  }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(env.CAPABILITY_ACTIVE_KEY_ID)) {
    throw new Error("CAPABILITY_ACTIVE_KEY_ID is invalid");
  }

  const capabilityKeys = parseCapabilityKeyring(env.CAPABILITY_HMAC_KEYRING);
  const activeCapabilityKey = capabilityKeys.get(env.CAPABILITY_ACTIVE_KEY_ID);
  if (activeCapabilityKey === undefined) {
    throw new Error("CAPABILITY_ACTIVE_KEY_ID is absent from CAPABILITY_HMAC_KEYRING");
  }
  return {
    activeCapabilityKey,
    activeCapabilityKeyId: env.CAPABILITY_ACTIVE_KEY_ID,
    capabilityKeys,
    expectedOrigin,
    permitIssuanceKey: decodeSecret(env.PERMIT_ISSUANCE_KEY, "PERMIT_ISSUANCE_KEY"),
    rateLimitKey: decodeSecret(env.RATE_LIMIT_KEY, "RATE_LIMIT_KEY"),
    turnstileAction: "create_permit",
    turnstileHostname: env.TURNSTILE_EXPECTED_HOSTNAME,
    turnstileSecretKey: env.TURNSTILE_SECRET_KEY
  };
}
