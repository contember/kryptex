import { describe, expect, test } from "vitest";
import serverVectors from "../../../vectors/v1/server-tags.json";
import {
  blindedLocator,
  capabilityTag,
  decodeUuid,
  derivePermitMaterial,
  encodeBase64Url,
  verifyCapabilityTag
} from "./core.js";
import { decodeCanonicalBase64Url } from "./strict.js";

function hexBytes(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/u.test(hex)) {
    throw new Error("invalid test hex");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.byteLength; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function resourceKind(value: number): 1 | 2 | 3 {
  if (value === 1 || value === 2 || value === 3) {
    return value;
  }
  throw new Error("invalid vector resource kind");
}

function capabilityKind(value: number): 1 | 2 | 3 {
  if (value === 1 || value === 2 || value === 3) {
    return value;
  }
  throw new Error("invalid vector capability kind");
}

describe("server protocol primitives", () => {
  test("matches every frozen capability tag", async () => {
    const key = hexBytes(serverVectors.serverKeyHex);
    for (const vector of serverVectors.capabilityTags) {
      const locator = decodeCanonicalBase64Url(vector.locatorBase64url, 16, "vector locator");
      const token = decodeCanonicalBase64Url(vector.tokenBase64url, 32, "vector token");
      const tag = await capabilityTag(
        key,
        resourceKind(vector.resourceKind),
        capabilityKind(vector.capabilityKind),
        locator,
        token
      );
      expect(decodeCanonicalBase64Url(tag, 32, "computed tag")).toEqual(hexBytes(vector.tagHex));
      expect(
        await verifyCapabilityTag(
          key,
          tag,
          resourceKind(vector.resourceKind),
          capabilityKind(vector.capabilityKind),
          locator,
          token
        )
      ).toBe(true);
    }
  });

  test("matches frozen locator blinds", async () => {
    const key = hexBytes(serverVectors.rateLimitKeyHex);
    for (const vector of serverVectors.rateLimitTags) {
      const kind = resourceKind(vector.resourceKind);
      const locator = decodeCanonicalBase64Url(vector.locatorBase64url, 16, "vector locator");
      expect(await blindedLocator(key, kind, locator)).toBe(vector.tagBase64url);
    }
  });

  test("matches frozen create-permit derivation", async () => {
    const vector = serverVectors.createPermit;
    const material = await derivePermitMaterial(
      hexBytes(vector.issuanceKeyHex),
      decodeUuid("550e8400-e29b-41d4-a716-446655440000")
    );
    expect(encodeBase64Url(material.permitSeed)).toBe(encodeBase64Url(hexBytes(vector.permitSeedHex)));
    expect(encodeBase64Url(material.locator)).toBe(vector.permitLocatorBase64url);
    expect(encodeBase64Url(material.token)).toBe(vector.permitTokenBase64url);
  });
});
