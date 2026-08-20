import { describe, expect, test } from "vitest";
import envelopeVectors from "../../../vectors/v1/envelopes.json";
import negativeVectors from "../../../vectors/v1/negative.json";
import { parseKxe1Envelope, parseKxr1Envelope } from "./envelopes.js";
import { ALLOWED_KXE1_LENGTHS, ALLOWED_KXR1_LENGTHS } from "./protocol.js";

function decodeBase64Url(encoded: string): Uint8Array {
  const padding = "=".repeat((4 - (encoded.length % 4)) % 4);
  const binary = atob(encoded.replaceAll("-", "+").replaceAll("_", "/") + padding);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function encodeBase64Url(bytes: Uint8Array): string {
  const chunks: string[] = [];
  for (let offset = 0; offset < bytes.byteLength; offset += 32768) {
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 32768)));
  }
  return btoa(chunks.join("")).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function resizeKxe1(encoded: string, length: number): string {
  const source = decodeBase64Url(encoded);
  const resized = new Uint8Array(length);
  resized.set(source.subarray(0, 62));
  return encodeBase64Url(resized);
}

function resizeKxr1(encoded: string, length: number): string {
  const source = decodeBase64Url(encoded);
  const resized = new Uint8Array(length);
  resized.set(source.subarray(0, 86));
  new DataView(resized.buffer).setUint32(50, length - 86);
  return encodeBase64Url(resized);
}

describe("clear envelope headers", () => {
  test("parses every valid KXE1 vector", () => {
    for (const vector of envelopeVectors.kxe1) {
      const header = parseKxe1Envelope(vector.envelopeBase64url);
      expect(header.bytes.byteLength).toBe(vector.envelopeLength);
      expect(header.clientNotAfter).toBe(vector.clientNotAfter);
      expect(header.contentMode).toBe(vector.contentMode);
      expect(header.factorMode).toBe(vector.factorMode);
      expect(header.maxRetrievals).toBe(vector.maxRetrievals);
    }
  });

  test("parses the valid KXR1 vector", () => {
    const vector = envelopeVectors.kxr1;
    const header = parseKxr1Envelope(vector.envelopeBase64url);
    expect(header.bytes.byteLength).toBe(vector.envelopeLength);
    expect(header.ciphertextLength).toBe(vector.ciphertextLength);
    expect(header.clientNotAfter).toBe(vector.clientNotAfter);
  });

  test("accepts every allowed boundary length", () => {
    const send = envelopeVectors.kxe1[0];
    if (send === undefined) {
      throw new Error("missing KXE1 fixture");
    }
    for (const length of ALLOWED_KXE1_LENGTHS) {
      expect(parseKxe1Envelope(resizeKxe1(send.envelopeBase64url, length)).bytes.byteLength).toBe(length);
    }
    for (const length of ALLOWED_KXR1_LENGTHS) {
      expect(parseKxr1Envelope(resizeKxr1(envelopeVectors.kxr1.envelopeBase64url, length)).bytes.byteLength).toBe(length);
    }
  });

  test("rejects all clear-header KXE1 negative vectors", () => {
    const rejectedIds = new Set([
      "kxe-bad-magic",
      "kxe-bad-suite",
      "kxe-unsupported-content-mode",
      "kxe-unsupported-factor",
      "kxe-nonzero-flags",
      "kxe-unsafe-timestamp",
      "kxe-send-zero-retrievals",
      "kxe-send-too-many-retrievals",
      "kxe-send-nonzero-schema-digest",
      "kxe-schema-nonzero-retrievals",
      "kxe-truncated"
    ]);
    const vectors = negativeVectors.malformedContainers.filter((vector) => rejectedIds.has(vector.id));
    expect(vectors).toHaveLength(rejectedIds.size);
    for (const vector of vectors) {
      expect(() => parseKxe1Envelope(vector.valueBase64url), vector.id).toThrow();
    }
  });

  test("rejects every clear-header KXR1 negative vector", () => {
    const vectors = negativeVectors.malformedContainers.filter((vector) => vector.container === "KXR1");
    expect(vectors.length).toBeGreaterThan(0);
    for (const vector of vectors) {
      expect(() => parseKxr1Envelope(vector.valueBase64url), vector.id).toThrow();
    }
  });

  test("rejects cross-container envelope confusion", () => {
    expect(() => parseKxe1Envelope(envelopeVectors.kxr1.envelopeBase64url)).toThrow();
    expect(() => parseKxr1Envelope(envelopeVectors.kxe1[0]?.envelopeBase64url)).toThrow();
  });
});
