import type { FactorMode } from "@kryptex/contracts/protocol";
import type { RequestSchemaPayload, SendPayload } from "@kryptex/contracts/payloads";
import { concat, decodeBase64Url, equalBytes, owned, randomBytes, readU16, readU64, requireLength, requireTimestamp, sha256, writeU16, writeU64 } from "./bytes.js";
import { fail, opaqueFailure } from "./errors.js";
import { decodeRequestSchemaPayload, decodeSendPayload, encodePayload } from "./payloads.js";
import { decodePaddedPlaintext, encodePaddedPlaintext } from "./plaintext.js";

const headerLength = 62;
const allowedEnvelopeLengths = [4174, 16462, 65614, 262222, 1048654];

export interface Kxe1Header {
  readonly clientNotAfter: number;
  readonly contentMode: 1 | 2;
  readonly factorMode: FactorMode;
  readonly maxRetrievals: number;
  readonly nonce: Uint8Array<ArrayBuffer>;
  readonly schemaDigest: Uint8Array<ArrayBuffer>;
}

export interface EncryptSendOptions {
  readonly clientNotAfter: number;
  readonly contentKey: Uint8Array;
  readonly factorMode: FactorMode;
  readonly maxRetrievals: number;
  readonly payload: SendPayload;
}

export interface EncryptSchemaOptions {
  readonly clientNotAfter: number;
  readonly factorMode: FactorMode;
  readonly payload: RequestSchemaPayload;
  readonly schemaKey: Uint8Array;
}

function mode(value: number): 1 | 2 {
  if (value === 1 || value === 2) return value;
  return fail("invalid_envelope");
}

function factor(value: number): FactorMode {
  if (value === 0 || value === 1 || value === 2) return value;
  return fail("invalid_envelope");
}

function makeHeader(
  contentMode: 1 | 2,
  factorMode: FactorMode,
  clientNotAfter: number,
  maxRetrievals: number,
  schemaDigest: Uint8Array,
  nonce: Uint8Array
): Uint8Array<ArrayBuffer> {
  requireLength(schemaDigest, 32, "invalid_envelope");
  requireLength(nonce, 12, "invalid_envelope");
  const header = new Uint8Array(headerLength);
  header.set([0x4b, 0x58, 0x45, 0x31, 1, contentMode, factorMode, 0], 0);
  writeU64(header, 8, clientNotAfter);
  writeU16(header, 16, maxRetrievals);
  header.set(schemaDigest, 18);
  header.set(nonce, 50);
  return header;
}

export function parseKxe1Header(envelope: Uint8Array): Kxe1Header {
  if (!allowedEnvelopeLengths.includes(envelope.byteLength)) fail("invalid_envelope");
  if (envelope[0] !== 0x4b || envelope[1] !== 0x58 || envelope[2] !== 0x45 || envelope[3] !== 0x31 || envelope[4] !== 1) {
    fail("invalid_envelope");
  }
  if (envelope[7] !== 0) fail("invalid_envelope");
  const contentMode = mode(envelope[5] ?? -1);
  const factorMode = factor(envelope[6] ?? -1);
  const maxRetrievals = readU16(envelope, 16);
  const schemaDigest = envelope.slice(18, 50);
  if (contentMode === 1) {
    if (maxRetrievals < 1 || maxRetrievals > 10 || schemaDigest.some((byte) => byte !== 0)) fail("invalid_envelope");
  } else if (maxRetrievals !== 0) fail("invalid_envelope");
  return {
    clientNotAfter: readU64(envelope, 8),
    contentMode,
    factorMode,
    maxRetrievals,
    nonce: envelope.slice(50, 62),
    schemaDigest
  };
}

async function aesEncrypt(keyBytes: Uint8Array, header: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  requireLength(keyBytes, 32, "invalid_key");
  const key = await crypto.subtle.importKey("raw", owned(keyBytes), "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv: owned(header.slice(50, 62)),
    additionalData: owned(header),
    tagLength: 128
  }, key, owned(plaintext));
  return new Uint8Array(encrypted);
}

async function aesDecrypt(keyBytes: Uint8Array, envelope: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  requireLength(keyBytes, 32, "invalid_key");
  const key = await crypto.subtle.importKey("raw", owned(keyBytes), "AES-GCM", false, ["decrypt"]);
  return opaqueFailure(async () => new Uint8Array(await crypto.subtle.decrypt({
    name: "AES-GCM",
    iv: owned(envelope.slice(50, 62)),
    additionalData: owned(envelope.slice(0, headerLength)),
    tagLength: 128
  }, key, owned(envelope.slice(headerLength)))), "decryption_failed");
}

async function encryptSendEnvelopeWithNonce(
  options: EncryptSendOptions,
  nonce: Uint8Array,
  paddingSource?: (length: number) => Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  if (options.maxRetrievals < 1 || options.maxRetrievals > 10 || !Number.isInteger(options.maxRetrievals)) fail("invalid_retrieval_count");
  const payload = encodePayload(options.payload);
  const header = makeHeader(1, options.factorMode, options.clientNotAfter, options.maxRetrievals, new Uint8Array(32), nonce);
  const plaintext = encodePaddedPlaintext(payload, paddingSource);
  return concat(header, await aesEncrypt(options.contentKey, header, plaintext));
}

async function encryptRequestSchemaEnvelopeWithNonce(
  options: EncryptSchemaOptions,
  nonce: Uint8Array,
  paddingSource?: (length: number) => Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  const payload = encodePayload(options.payload);
  const header = makeHeader(2, options.factorMode, options.clientNotAfter, 0, await sha256(payload), nonce);
  const plaintext = encodePaddedPlaintext(payload, paddingSource);
  return concat(header, await aesEncrypt(options.schemaKey, header, plaintext));
}

export function encryptSendEnvelope(options: EncryptSendOptions): Promise<Uint8Array<ArrayBuffer>> {
  return encryptSendEnvelopeWithNonce(options, randomBytes(12), undefined);
}

export function encryptRequestSchemaEnvelope(options: EncryptSchemaOptions): Promise<Uint8Array<ArrayBuffer>> {
  return encryptRequestSchemaEnvelopeWithNonce(options, randomBytes(12), undefined);
}

export function encryptSendEnvelopeWithTestNonce(
  options: EncryptSendOptions,
  testNonce: Uint8Array,
  paddingSource: (length: number) => Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  return encryptSendEnvelopeWithNonce(options, owned(testNonce), paddingSource);
}

export function encryptRequestSchemaEnvelopeWithTestNonce(
  options: EncryptSchemaOptions,
  testNonce: Uint8Array,
  paddingSource: (length: number) => Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  return encryptRequestSchemaEnvelopeWithNonce(options, owned(testNonce), paddingSource);
}

function checkContext(header: Kxe1Header, expectedMode: 1 | 2, factorMode: FactorMode, serverExpiresAt: number, nowSeconds: number): void {
  requireTimestamp(header.clientNotAfter);
  requireTimestamp(serverExpiresAt);
  requireTimestamp(nowSeconds);
  if (header.contentMode !== expectedMode || header.factorMode !== factorMode) fail("context_mismatch");
  if (nowSeconds >= Math.min(header.clientNotAfter, serverExpiresAt)) {
    fail("expired");
  }
}

export async function decryptSendEnvelope(
  envelope: Uint8Array,
  contentKey: Uint8Array,
  factorMode: FactorMode,
  serverExpiresAt: number,
  nowSeconds: number
): Promise<{ readonly header: Kxe1Header; readonly payload: SendPayload }> {
  const bytes = owned(envelope);
  const header = parseKxe1Header(bytes);
  checkContext(header, 1, factorMode, serverExpiresAt, nowSeconds);
  const payload = decodeSendPayload(decodePaddedPlaintext(await aesDecrypt(contentKey, bytes)));
  return { header, payload };
}

export async function decryptRequestSchemaEnvelope(
  envelope: Uint8Array,
  schemaKey: Uint8Array,
  factorMode: FactorMode,
  expectedRecipientPublicKey: Uint8Array,
  serverExpiresAt: number,
  nowSeconds: number
): Promise<{ readonly header: Kxe1Header; readonly payload: RequestSchemaPayload }> {
  requireLength(expectedRecipientPublicKey, 32, "context_mismatch");
  const bytes = owned(envelope);
  const header = parseKxe1Header(bytes);
  checkContext(header, 2, factorMode, serverExpiresAt, nowSeconds);
  const payloadBytes = decodePaddedPlaintext(await aesDecrypt(schemaKey, bytes));
  if (!equalBytes(await sha256(payloadBytes), header.schemaDigest)) fail("decryption_failed");
  const payload = decodeRequestSchemaPayload(payloadBytes);
  const publicKey = decodeBase64Url(payload.recipientPublicKey);
  if (!equalBytes(publicKey, expectedRecipientPublicKey)) fail("context_mismatch");
  return { header, payload };
}
