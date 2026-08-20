import type { FactorMode } from "@kryptex/contracts/protocol";
import { concat, owned, requireLength, sha256, utf8 } from "./bytes.js";
import { factorForMode } from "./factors.js";
import { fail } from "./errors.js";

async function hmac(key: Uint8Array, input: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const imported = await crypto.subtle.importKey("raw", owned(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, owned(input)));
}

export async function hkdfExtract(label: string, input: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return hmac(await sha256(utf8(label)), input);
}

export async function hkdfExpand(prk: Uint8Array, label: string, length: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!Number.isInteger(length) || length < 0 || length > 8160) fail("invalid_hkdf_length");
  const info = utf8(label);
  let previous = new Uint8Array();
  let output = new Uint8Array();
  let counter = 1;
  while (output.byteLength < length) {
    previous = await hmac(prk, concat(previous, info, Uint8Array.of(counter)));
    output = concat(output, previous);
    counter += 1;
  }
  return output.slice(0, length);
}

function factorName(mode: FactorMode): string {
  if (mode === 0) return "none";
  if (mode === 1) return "passphrase";
  return "random-factor";
}

export interface SendKeys {
  readonly contentKey: Uint8Array<ArrayBuffer>;
  readonly locator: Uint8Array<ArrayBuffer>;
  readonly manageToken: Uint8Array<ArrayBuffer>;
  readonly retrieveToken: Uint8Array<ArrayBuffer>;
}

export async function deriveSendKeys(
  sendSeed: Uint8Array,
  manageSeed: Uint8Array,
  factorMode: FactorMode,
  factor?: Uint8Array
): Promise<SendKeys> {
  requireLength(sendSeed, 32, "invalid_send_seed");
  requireLength(manageSeed, 32, "invalid_manage_seed");
  const locatorPrk = await hkdfExtract("kryptex/v1/send/locator", sendSeed);
  const masterLabel = `kryptex/v1/send/master/${factorName(factorMode)}`;
  const masterPrk = await hkdfExtract(masterLabel, concat(sendSeed, factorForMode(factorMode, factor)));
  const managePrk = await hkdfExtract("kryptex/v1/send/manage-token", manageSeed);
  return {
    contentKey: await hkdfExpand(masterPrk, "kryptex/v1/send/content-key", 32),
    locator: await hkdfExpand(locatorPrk, "kryptex/v1/send/locator", 16),
    manageToken: await hkdfExpand(managePrk, "kryptex/v1/send/manage-token", 32),
    retrieveToken: await hkdfExpand(masterPrk, "kryptex/v1/send/retrieve-token", 32)
  };
}

export interface RequestWriteKeys {
  readonly schemaKey: Uint8Array<ArrayBuffer>;
  readonly writeToken: Uint8Array<ArrayBuffer>;
}

export async function deriveRequestWriteKeys(
  writeSeed: Uint8Array,
  factorMode: FactorMode,
  factor?: Uint8Array
): Promise<RequestWriteKeys> {
  requireLength(writeSeed, 32, "invalid_write_seed");
  const label = `kryptex/v1/request/write-master/${factorName(factorMode)}`;
  const prk = await hkdfExtract(label, concat(writeSeed, factorForMode(factorMode, factor)));
  return {
    schemaKey: await hkdfExpand(prk, "kryptex/v1/request/schema-key", 32),
    writeToken: await hkdfExpand(prk, "kryptex/v1/request/write-token", 32)
  };
}

export interface RequestOwnerKeys {
  readonly hpkeIkm: Uint8Array<ArrayBuffer>;
  readonly ownerToken: Uint8Array<ArrayBuffer>;
}

export async function deriveRequestOwnerKeys(ownerSeed: Uint8Array): Promise<RequestOwnerKeys> {
  requireLength(ownerSeed, 32, "invalid_owner_seed");
  const prk = await hkdfExtract("kryptex/v1/request/owner-token", ownerSeed);
  return {
    hpkeIkm: await hkdfExpand(prk, "kryptex/v1/request/hpke-keypair", 32),
    ownerToken: await hkdfExpand(prk, "kryptex/v1/request/owner-token", 32)
  };
}

export async function deriveCapabilityTag(
  serverKey: Uint8Array,
  resourceKind: 1 | 2 | 3,
  capabilityKind: 1 | 2 | 3,
  locator: Uint8Array,
  token: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  requireLength(serverKey, 32);
  requireLength(locator, 16);
  requireLength(token, 32);
  return hmac(serverKey, concat(utf8("kryptex/v1/server-capability-tag"), Uint8Array.of(0, resourceKind, capabilityKind), locator, token));
}

export async function deriveRateLimitTag(
  rateLimitKey: Uint8Array,
  resourceKind: 1 | 2 | 3,
  locator: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  requireLength(rateLimitKey, 32);
  requireLength(locator, 16);
  return hmac(rateLimitKey, concat(utf8("kryptex/v1/rate-limit-locator"), Uint8Array.of(0, resourceKind), locator));
}

export interface CreatePermitKeys {
  readonly locator: Uint8Array<ArrayBuffer>;
  readonly token: Uint8Array<ArrayBuffer>;
}

export async function deriveCreatePermitKeys(permitSeed: Uint8Array): Promise<CreatePermitKeys> {
  requireLength(permitSeed, 32, "invalid_permit_seed");
  const prk = await hkdfExtract("kryptex/v1/create-permit/locator", permitSeed);
  return {
    locator: await hkdfExpand(prk, "kryptex/v1/create-permit/locator", 16),
    token: await hkdfExpand(prk, "kryptex/v1/create-permit/token", 32)
  };
}

export async function deriveCreatePermitSeed(issuanceKey: Uint8Array, requestId: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  requireLength(issuanceKey, 32, "invalid_issuance_key");
  requireLength(requestId, 16, "invalid_request_id");
  return hmac(issuanceKey, concat(utf8("kryptex/v1/create-permit/issuance"), Uint8Array.of(0), requestId));
}
