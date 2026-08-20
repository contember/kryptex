export type FactorMode = 0 | 1 | 2;
export type ContentMode = 1 | 2;
export type BundleKind = 1 | 2 | 3 | 4;
export type ResourceKind = 1 | 2 | 3;
export type CapabilityKind = 1 | 2 | 3;
export type TtlSeconds = 900 | 3600 | 28800 | 86400 | 259200 | 604800;

export const PROTOCOL_VERSION = 1;
export const KXB1_MAGIC = "KXB1";
export const KXE1_MAGIC = "KXE1";
export const KXR1_MAGIC = "KXR1";

export const FACTOR_MODE_NONE: FactorMode = 0;
export const FACTOR_MODE_PASSPHRASE: FactorMode = 1;
export const FACTOR_MODE_RANDOM: FactorMode = 2;
export const CONTENT_MODE_SEND: ContentMode = 1;
export const CONTENT_MODE_REQUEST_SCHEMA: ContentMode = 2;

export const LOCATOR_BYTE_LENGTH = 16;
export const TOKEN_BYTE_LENGTH = 32;
export const DIGEST_BYTE_LENGTH = 32;
export const FACTOR_BYTE_LENGTH = 32;
export const SALT_BYTE_LENGTH = 16;
export const REQUEST_ID_BYTE_LENGTH = 16;

export const ALLOWED_TTL_SECONDS: readonly number[] = Object.freeze([
  900,
  3600,
  28800,
  86400,
  259200,
  604800
]);
export const ALLOWED_PLAINTEXT_BUCKET_LENGTHS: readonly number[] = Object.freeze([
  4096,
  16384,
  65536,
  262144,
  1048576
]);
export const ALLOWED_KXE1_LENGTHS: readonly number[] = Object.freeze([
  4174,
  16462,
  65614,
  262222,
  1048654
]);
export const ALLOWED_KXR1_LENGTHS: readonly number[] = Object.freeze([
  4198,
  16486,
  65638,
  262246,
  1048678
]);

export const MAX_KXE1_LENGTH = 1048654;
export const MAX_KXR1_LENGTH = 1048678;
export const MIN_PASSPHRASE_UTF8_BYTES = 12;
export const MAX_PASSPHRASE_UTF8_BYTES = 256;
export const MAX_FIELDS = 32;
export const MAX_LABEL_UTF8_BYTES = 120;
export const MAX_HELP_UTF8_BYTES = 500;
export const MAX_VALUE_UTF8_BYTES = 262144;

export const API_ROUTES = Object.freeze({
  createPermit: "/api/v1/create-permits",
  createPermitStatus: "/api/v1/create-permits/status",
  requestCreate: "/api/v1/requests",
  requestPickup: "/api/v1/requests/pickup",
  requestRevoke: "/api/v1/requests/revoke",
  requestSchema: "/api/v1/requests/schema",
  requestShorten: "/api/v1/requests/shorten",
  requestStatus: "/api/v1/requests/status",
  requestSubmit: "/api/v1/requests/submit",
  sendCreate: "/api/v1/sends",
  sendRetrieve: "/api/v1/sends/retrieve",
  sendRevoke: "/api/v1/sends/revoke",
  sendShorten: "/api/v1/sends/shorten",
  sendStatus: "/api/v1/sends/status"
});

export const RESPONSE_HEADERS = Object.freeze({
  cacheControl: "Cache-Control",
  contentTypeOptions: "X-Content-Type-Options",
  receipt: "Kryptex-Receipt",
  referrerPolicy: "Referrer-Policy",
  remainingReleases: "Kryptex-Remaining-Releases",
  serverExpiresAt: "Kryptex-Server-Expires-At",
  serverTime: "Kryptex-Server-Time",
  stateCheckedAt: "Kryptex-State-Checked-At"
});

export function isTtlSeconds(value: number): value is TtlSeconds {
  return value === 900 || value === 3600 || value === 28800 || value === 86400 || value === 259200 || value === 604800;
}
