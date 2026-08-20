import { describe, expect, test } from "vitest";
import keyVectors from "../../../vectors/v1/key-schedules.json";
import {
  deriveSendKeys,
  deriveSendManagementKeys,
  deriveSendRecipientKeys,
  encodeBase64Url,
  equalBytes
} from "./index.js";

function fromHex(value: string): Uint8Array<ArrayBuffer> {
  if (value.length % 2 !== 0) throw new Error("invalid test hex");
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("independent send bundle key schedules", () => {
  test("matches every frozen recipient and management vector", async () => {
    const sendSeed = fromHex(keyVectors.sendSeedHex);
    const manageSeed = fromHex(keyVectors.manageSeedHex);
    for (const fixture of keyVectors.send) {
      if (fixture.factorMode !== 0 && fixture.factorMode !== 1 && fixture.factorMode !== 2) {
        throw new Error("bad vector mode");
      }
      const recipient = await deriveSendRecipientKeys(sendSeed, fixture.factorMode, fromHex(fixture.factorHex));
      const management = await deriveSendManagementKeys(manageSeed);
      expect(recipient.locator, fixture.factorModeName).toHaveLength(16);
      expect(encodeBase64Url(recipient.locator), fixture.factorModeName).toBe(fixture.locatorBase64url);
      expect(hex(recipient.contentKey), fixture.factorModeName).toBe(fixture.contentKeyHex);
      expect(encodeBase64Url(recipient.retrieveToken), fixture.factorModeName).toBe(fixture.retrieveTokenBase64url);
      expect(encodeBase64Url(management.manageToken), fixture.factorModeName).toBe(fixture.manageTokenBase64url);
    }
  });

  test("composes to the legacy combined schedule for every factor mode", async () => {
    const sendSeed = fromHex(keyVectors.sendSeedHex);
    const manageSeed = fromHex(keyVectors.manageSeedHex);
    for (const fixture of keyVectors.send) {
      if (fixture.factorMode !== 0 && fixture.factorMode !== 1 && fixture.factorMode !== 2) {
        throw new Error("bad vector mode");
      }
      const factor = fromHex(fixture.factorHex);
      const recipient = await deriveSendRecipientKeys(sendSeed, fixture.factorMode, factor);
      const management = await deriveSendManagementKeys(manageSeed);
      const combined = await deriveSendKeys(sendSeed, manageSeed, fixture.factorMode, factor);
      expect(equalBytes(combined.contentKey, recipient.contentKey), fixture.factorModeName).toBe(true);
      expect(equalBytes(combined.locator, recipient.locator), fixture.factorModeName).toBe(true);
      expect(equalBytes(combined.retrieveToken, recipient.retrieveToken), fixture.factorModeName).toBe(true);
      expect(equalBytes(combined.manageToken, management.manageToken), fixture.factorModeName).toBe(true);
    }
  });

  test("rejects invalid seed and factor lengths independently", async () => {
    await expect(deriveSendRecipientKeys(new Uint8Array(31), 0)).rejects.toMatchObject({ code: "invalid_send_seed" });
    await expect(deriveSendManagementKeys(new Uint8Array(31))).rejects.toMatchObject({ code: "invalid_manage_seed" });
    await expect(deriveSendRecipientKeys(new Uint8Array(32), 1)).rejects.toMatchObject({ code: "factor_required" });
    await expect(deriveSendRecipientKeys(new Uint8Array(32), 1, new Uint8Array(31))).rejects.toMatchObject({ code: "invalid_factor" });
    await expect(deriveSendRecipientKeys(new Uint8Array(32), 2)).rejects.toMatchObject({ code: "factor_required" });
    await expect(deriveSendRecipientKeys(new Uint8Array(32), 2, new Uint8Array(33))).rejects.toMatchObject({ code: "invalid_factor" });
    await expect(deriveSendKeys(new Uint8Array(32), new Uint8Array(31), 0)).rejects.toMatchObject({ code: "invalid_manage_seed" });
  });
});
