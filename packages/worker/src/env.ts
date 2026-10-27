import { parseApiJsonText } from "@kryptex/contracts/api";

export interface WorkerSecurityEnvironment {
  readonly CAPABILITY_ACTIVE_KEY_ID: string;
  readonly CAPABILITY_HMAC_KEYRING: string;
  readonly EXPECTED_ORIGIN: string;
  readonly PERMIT_ISSUANCE_ACTIVE_KEY_ID: string;
  readonly PERMIT_ISSUANCE_KEYRING: string;
  readonly RATE_LIMIT_KEY: string;
  readonly TURNSTILE_EXPECTED_ACTION: string;
  readonly TURNSTILE_EXPECTED_HOSTNAME: string;
  readonly TURNSTILE_SECRET_KEY: string;
}

export interface WorkerEnv extends WorkerSecurityEnvironment {
  readonly ASSETS: Fetcher;
  readonly CIPHERTEXT: R2Bucket;
  readonly CREATE_PERMIT_OBJECTS: DurableObjectNamespace;
  readonly EDGE_RATE_LIMITER: RateLimit;
  readonly LOCATOR_RATE_LIMITER: RateLimit;
  readonly PAIRING_OBJECTS: DurableObjectNamespace;
  readonly REQUEST_OBJECTS: DurableObjectNamespace;
  readonly SEND_OBJECTS: DurableObjectNamespace;
}

export interface CheckedWorkerEnvironment {
  readonly activeCapabilityKey: Uint8Array;
  readonly activeCapabilityKeyId: string;
  readonly capabilityKeys: ReadonlyMap<string, Uint8Array>;
  readonly expectedOrigin: string;
  readonly activePermitIssuanceKey: Uint8Array;
  readonly activePermitIssuanceKeyId: string;
  readonly permitIssuanceKeys: ReadonlyMap<string, Uint8Array>;
  readonly rateLimitKey: Uint8Array;
  readonly localTurnstileDummy: boolean;
  readonly turnstileAction: "create_permit";
  readonly turnstileHostname: string;
  readonly turnstileSecretKey: string;
}

export const LOCAL_TURNSTILE_DUMMY_SECRET = "1x0000000000000000000000000000000AA";

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

function parseKeyring(text: string, name: string): ReadonlyMap<string, Uint8Array> {
  return parseApiJsonText(text, (value) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`${name} must be a JSON object`);
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length === 0 || keys.some((key) => typeof key !== "string")) {
      throw new Error(`${name} must contain named keys`);
    }
    const result = new Map<string, Uint8Array>();
    for (const key of keys) {
      if (typeof key !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(key)) {
        throw new Error(`${name} contains an invalid key ID`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error(`${name} contains an invalid property`);
      }
      result.set(key, decodeSecret(descriptor.value, `${name}.${key}`));
    }
    return result;
  });
}

export function checkWorkerEnvironment(env: WorkerSecurityEnvironment): CheckedWorkerEnvironment {
  let expectedOrigin: string;
  let expectedOriginHostname: string;
  try {
    const url = new URL(env.EXPECTED_ORIGIN);
    if ((url.protocol !== "https:" && !(url.protocol === "http:" && url.hostname === "localhost")) || url.origin !== env.EXPECTED_ORIGIN) {
      throw new Error("invalid origin");
    }
    expectedOrigin = url.origin;
    expectedOriginHostname = url.hostname;
  } catch {
    throw new Error("EXPECTED_ORIGIN must be an exact HTTPS origin or an HTTP localhost origin");
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
  const localTurnstileDummy = env.TURNSTILE_SECRET_KEY === LOCAL_TURNSTILE_DUMMY_SECRET;
  if (localTurnstileDummy && (expectedOriginHostname !== "localhost" || env.TURNSTILE_EXPECTED_HOSTNAME !== "localhost")) {
    throw new Error("The Turnstile dummy secret is restricted to localhost");
  }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(env.CAPABILITY_ACTIVE_KEY_ID)) {
    throw new Error("CAPABILITY_ACTIVE_KEY_ID is invalid");
  }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(env.PERMIT_ISSUANCE_ACTIVE_KEY_ID)) {
    throw new Error("PERMIT_ISSUANCE_ACTIVE_KEY_ID is invalid");
  }

  const capabilityKeys = parseKeyring(env.CAPABILITY_HMAC_KEYRING, "CAPABILITY_HMAC_KEYRING");
  const activeCapabilityKey = capabilityKeys.get(env.CAPABILITY_ACTIVE_KEY_ID);
  if (activeCapabilityKey === undefined) {
    throw new Error("CAPABILITY_ACTIVE_KEY_ID is absent from CAPABILITY_HMAC_KEYRING");
  }
  const permitIssuanceKeys = parseKeyring(env.PERMIT_ISSUANCE_KEYRING, "PERMIT_ISSUANCE_KEYRING");
  const activePermitIssuanceKey = permitIssuanceKeys.get(env.PERMIT_ISSUANCE_ACTIVE_KEY_ID);
  if (activePermitIssuanceKey === undefined) {
    throw new Error("PERMIT_ISSUANCE_ACTIVE_KEY_ID is absent from PERMIT_ISSUANCE_KEYRING");
  }
  return {
    activeCapabilityKey,
    activeCapabilityKeyId: env.CAPABILITY_ACTIVE_KEY_ID,
    activePermitIssuanceKey,
    activePermitIssuanceKeyId: env.PERMIT_ISSUANCE_ACTIVE_KEY_ID,
    capabilityKeys,
    expectedOrigin,
    localTurnstileDummy,
    permitIssuanceKeys,
    rateLimitKey: decodeSecret(env.RATE_LIMIT_KEY, "RATE_LIMIT_KEY"),
    turnstileAction: "create_permit",
    turnstileHostname: env.TURNSTILE_EXPECTED_HOSTNAME,
    turnstileSecretKey: env.TURNSTILE_SECRET_KEY
  };
}
