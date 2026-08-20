import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import type { RequestResponsePayload } from "@kryptex/contracts/payloads";
import { concat, decodeBase64Url, encodeBase64Url, equalBytes, owned, readU32, readU64, requireLength, requireTimestamp, sha256, utf8, writeU16, writeU32, writeU64 } from "./bytes.js";
import { fail, opaqueFailure } from "./errors.js";
import { decodeRequestResponsePayload, encodePayload } from "./payloads.js";
import { decodePaddedPlaintext, encodePaddedPlaintext } from "./plaintext.js";

const hpkeSuite = new CipherSuite({
  aead: new Aes256Gcm(),
  kdf: new HkdfSha256(),
  kem: new DhkemX25519HkdfSha256()
});
const headerLength = 86;
const allowedEnvelopeLengths = [4198, 16486, 65638, 262246, 1048678];

export interface HpkeKeyPairBytes {
  readonly privateKey: Uint8Array<ArrayBuffer>;
  readonly publicKey: Uint8Array<ArrayBuffer>;
}

export interface Kxr1Header {
  readonly ciphertextLength: number;
  readonly clientNotAfter: number;
  readonly enc: Uint8Array<ArrayBuffer>;
  readonly schemaDigest: Uint8Array<ArrayBuffer>;
}

export async function deriveHpkeKeyPair(hpkeIkm: Uint8Array): Promise<HpkeKeyPairBytes> {
  requireLength(hpkeIkm, 32, "invalid_hpke_seed");
  return opaqueFailure(async () => {
    const pair = await hpkeSuite.kem.deriveKeyPair(owned(hpkeIkm));
    return {
      privateKey: new Uint8Array(await hpkeSuite.kem.serializePrivateKey(pair.privateKey)),
      publicKey: new Uint8Array(await hpkeSuite.kem.serializePublicKey(pair.publicKey))
    };
  });
}

function hpkeInfo(requestLocator: Uint8Array, schemaDigest: Uint8Array): Uint8Array<ArrayBuffer> {
  requireLength(requestLocator, 16, "context_mismatch");
  requireLength(schemaDigest, 32, "context_mismatch");
  return concat(utf8("kryptex/v1/request/response"), requestLocator, schemaDigest);
}

function makeHeader(
  clientNotAfter: number,
  schemaDigest: Uint8Array,
  ciphertextLength: number,
  enc: Uint8Array
): Uint8Array<ArrayBuffer> {
  requireLength(schemaDigest, 32, "invalid_envelope");
  requireLength(enc, 32, "invalid_envelope");
  const header = new Uint8Array(headerLength);
  header.set([0x4b, 0x58, 0x52, 0x31, 1, 0, 0, 0], 0);
  writeU64(header, 8, clientNotAfter);
  header.set(schemaDigest, 16);
  writeU16(header, 48, 32);
  writeU32(header, 50, ciphertextLength);
  header.set(enc, 54);
  return header;
}

export function parseKxr1Header(envelope: Uint8Array): Kxr1Header {
  if (!allowedEnvelopeLengths.includes(envelope.byteLength)) fail("invalid_envelope");
  if (
    envelope[0] !== 0x4b || envelope[1] !== 0x58 || envelope[2] !== 0x52 || envelope[3] !== 0x31 ||
    envelope[4] !== 1 || envelope[5] !== 0 || envelope[6] !== 0 || envelope[7] !== 0
  ) fail("invalid_envelope");
  const encLength = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength).getUint16(48);
  const ciphertextLength = readU32(envelope, 50);
  if (encLength !== 32 || ciphertextLength !== envelope.byteLength - headerLength || ![4112, 16400, 65552, 262160, 1048592].includes(ciphertextLength)) {
    fail("invalid_envelope");
  }
  return {
    ciphertextLength,
    clientNotAfter: readU64(envelope, 8),
    enc: envelope.slice(54, 86),
    schemaDigest: envelope.slice(16, 48)
  };
}

export interface SealResponseOptions {
  readonly expectedClientNotAfter: number;
  readonly payload: RequestResponsePayload;
  readonly recipientPublicKey: Uint8Array;
  readonly requestLocator: Uint8Array;
  readonly schemaDigest: Uint8Array;
}

async function sealRequestResponseWithEntropy(
  options: SealResponseOptions,
  paddingSource: ((length: number) => Uint8Array) | undefined,
  testEkm: Uint8Array | undefined
): Promise<Uint8Array<ArrayBuffer>> {
  requireTimestamp(options.expectedClientNotAfter);
  requireLength(options.recipientPublicKey, 32, "context_mismatch");
  const schemaBytes = encodePayload(options.payload.schema);
  if (!equalBytes(await sha256(schemaBytes), options.schemaDigest)) fail("context_mismatch");
  if (!equalBytes(decodeBase64Url(options.payload.schema.recipientPublicKey), options.recipientPublicKey)) fail("context_mismatch");
  const plaintext = encodePaddedPlaintext(encodePayload(options.payload), paddingSource);
  return opaqueFailure(async () => {
    const publicKey = await hpkeSuite.kem.deserializePublicKey(owned(options.recipientPublicKey));
    const sender = await hpkeSuite.createSenderContext({
      ...(testEkm === undefined ? {} : { ekm: owned(testEkm) }),
      info: hpkeInfo(options.requestLocator, options.schemaDigest),
      recipientPublicKey: publicKey
    });
    const enc = new Uint8Array(sender.enc);
    const header = makeHeader(options.expectedClientNotAfter, options.schemaDigest, plaintext.byteLength + 16, enc);
    const ciphertext = new Uint8Array(await sender.seal(plaintext, header));
    if (ciphertext.byteLength !== plaintext.byteLength + 16) fail("crypto_failed");
    return concat(header, ciphertext);
  });
}

export function sealRequestResponse(options: SealResponseOptions): Promise<Uint8Array<ArrayBuffer>> {
  return sealRequestResponseWithEntropy(options, undefined, undefined);
}

export function sealRequestResponseWithTestEntropy(
  options: SealResponseOptions,
  testEkm: Uint8Array,
  paddingSource: (length: number) => Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  requireLength(testEkm, 32, "invalid_test_entropy");
  return sealRequestResponseWithEntropy(options, paddingSource, testEkm);
}

export interface OpenResponseOptions {
  readonly envelope: Uint8Array;
  readonly expectedClientNotAfter: number;
  readonly hpkeIkm: Uint8Array;
  readonly nowSeconds: number;
  readonly requestLocator: Uint8Array;
  readonly serverExpiresAt: number;
}

export async function openRequestResponse(
  options: OpenResponseOptions
): Promise<{ readonly header: Kxr1Header; readonly payload: RequestResponsePayload; readonly receipt: Uint8Array<ArrayBuffer> }> {
  const envelope = owned(options.envelope);
  const header = parseKxr1Header(envelope);
  requireTimestamp(options.expectedClientNotAfter);
  requireTimestamp(options.nowSeconds);
  requireTimestamp(options.serverExpiresAt);
  if (header.clientNotAfter !== options.expectedClientNotAfter) fail("context_mismatch");
  if (options.nowSeconds >= Math.min(header.clientNotAfter, options.serverExpiresAt)) fail("expired");
  const keyPair = await deriveHpkeKeyPair(options.hpkeIkm);
  const plaintext = await opaqueFailure(async () => {
    const privateKey = await hpkeSuite.kem.deserializePrivateKey(keyPair.privateKey);
    const recipient = await hpkeSuite.createRecipientContext({
      enc: header.enc,
      info: hpkeInfo(options.requestLocator, header.schemaDigest),
      recipientKey: privateKey
    });
    return new Uint8Array(await recipient.open(envelope.slice(headerLength), envelope.slice(0, headerLength)));
  }, "decryption_failed");
  const payload = decodeRequestResponsePayload(decodePaddedPlaintext(plaintext));
  if (!equalBytes(await sha256(encodePayload(payload.schema)), header.schemaDigest)) fail("context_mismatch");
  if (!equalBytes(decodeBase64Url(payload.schema.recipientPublicKey), keyPair.publicKey)) fail("context_mismatch");
  return { header, payload, receipt: await sha256(envelope) };
}

export async function receiptBase64Url(envelope: Uint8Array): Promise<string> {
  return encodeBase64Url(await sha256(envelope));
}

export async function receiptDisplay(envelope: Uint8Array): Promise<string> {
  const digest = await sha256(envelope);
  const compact = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  return compact.match(/.{8}/gu)?.join(" ") ?? fail("receipt_failed");
}
