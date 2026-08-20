import { ALLOWED_PLAINTEXT_BUCKET_LENGTHS } from "@kryptex/contracts/protocol";
import { owned, randomBytes, readU32, writeU32 } from "./bytes.js";
import { fail } from "./errors.js";

export function selectBucketLength(payloadLength: number): number {
  if (!Number.isSafeInteger(payloadLength) || payloadLength < 0) fail("invalid_payload_length");
  const required = payloadLength + 4;
  const bucket = ALLOWED_PLAINTEXT_BUCKET_LENGTHS.find((length) => required <= length);
  if (bucket === undefined) return fail("payload_too_large");
  return bucket;
}

export function encodePaddedPlaintext(
  payload: Uint8Array,
  paddingSource: (length: number) => Uint8Array = randomBytes
): Uint8Array<ArrayBuffer> {
  const bucketLength = selectBucketLength(payload.byteLength);
  const paddingLength = bucketLength - payload.byteLength - 4;
  const padding = owned(paddingSource(paddingLength));
  if (padding.byteLength !== paddingLength) fail("invalid_padding");
  const output = new Uint8Array(bucketLength);
  writeU32(output, 0, payload.byteLength);
  output.set(payload, 4);
  output.set(padding, 4 + payload.byteLength);
  return output;
}

export function decodePaddedPlaintext(plaintext: Uint8Array): Uint8Array<ArrayBuffer> {
  if (!ALLOWED_PLAINTEXT_BUCKET_LENGTHS.includes(plaintext.byteLength)) fail("invalid_plaintext");
  const payloadLength = readU32(plaintext, 0);
  if (payloadLength > plaintext.byteLength - 4 || selectBucketLength(payloadLength) !== plaintext.byteLength) {
    fail("invalid_plaintext");
  }
  return plaintext.slice(4, 4 + payloadLength);
}
