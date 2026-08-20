import { describe, expect, it } from "vitest";
import type { RequestSchemaField } from "@kryptex/contracts/payloads";

import { isValidCrockfordFactor, normalizeCrockfordFactor, requiredArtifactsWording, requiredReceiptSaved, utf8ByteLength, validatePassphrase, validateRequestAnswers, validateRequestDraft, validateSendDraft } from "./validation";

describe("passphrase validation", () => {
  it("counts UTF-8 bytes rather than JavaScript characters", () => {
    expect(utf8ByteLength("příliš krátké")).toBe(18);
    expect(validatePassphrase("příliš krátké", "příliš krátké").valid).toBe(true);
  });

  it("requires 12 through 256 bytes and an exact confirmation", () => {
    expect(validatePassphrase("12345678901", "12345678901").valid).toBe(false);
    expect(validatePassphrase("123456789012", "123456789012").valid).toBe(true);
    expect(validatePassphrase("123456789012", "123456789013").valid).toBe(false);
    expect(validatePassphrase("x".repeat(257), "x".repeat(257)).valid).toBe(false);
  });
});

describe("receipt custody state", () => {
  it("requires the primary artifact and a separate generated factor when configured", () => {
    expect(requiredReceiptSaved(false, "second-key", true)).toBe(false);
    expect(requiredReceiptSaved(true, "second-key", false)).toBe(false);
    expect(requiredReceiptSaved(true, "second-key", true)).toBe(true);
    expect(requiredReceiptSaved(true, "passphrase", false)).toBe(true);
    expect(requiredReceiptSaved(true, "link-only", false)).toBe(true);
  });

  it("also requires a private pickup link when one is issued", () => {
    expect(requiredReceiptSaved(true, "second-key", true, false)).toBe(false);
    expect(requiredReceiptSaved(true, "second-key", true, true)).toBe(true);
    expect(requiredReceiptSaved(true, "passphrase", false, false)).toBe(false);
    expect(requiredReceiptSaved(true, "passphrase", false, true)).toBe(true);
  });

  it("describes one, two, and three required artifacts clearly", () => {
    expect(requiredArtifactsWording(1)).toBe("the required part");
    expect(requiredArtifactsWording(2)).toBe("both required parts");
    expect(requiredArtifactsWording(3)).toBe("all three required parts");
  });
});

describe("Crockford second-key validation", () => {
  const zeroFactor = "0".repeat(52);

  it("accepts ungrouped input and returns the canonical grouped display", () => {
    expect(normalizeCrockfordFactor(zeroFactor)).toBe("0000000000000-0000000000000-0000000000000-0000000000000");
  });

  it("accepts aliases and canonical hyphen positions", () => {
    expect(isValidCrockfordFactor("OOOOOOOOOOOOO-OOOOOOOOOOOOO-OOOOOOOOOOOOO-OOOOOOOOOOOOO")).toBe(true);
  });

  it("rejects short, misplaced, whitespace, U, and nonzero padding-bit input", () => {
    expect(isValidCrockfordFactor("0".repeat(12))).toBe(false);
    expect(isValidCrockfordFactor(`0-${"0".repeat(51)}`)).toBe(false);
    expect(isValidCrockfordFactor(`${"0".repeat(51)} `)).toBe(false);
    expect(isValidCrockfordFactor(`${"0".repeat(51)}U`)).toBe(false);
    expect(isValidCrockfordFactor(`${"0".repeat(51)}1`)).toBe(false);
  });
});

describe("local payload limits", () => {
  it("validates send text and structured fields in UTF-8 bytes", () => {
    expect(validateSendDraft("text", "x".repeat(262_144), []).valid).toBe(true);
    expect(validateSendDraft("text", `${"x".repeat(262_143)}€`, []).message).toContain("262144");
    expect(validateSendDraft("fields", "", [{ concealed: true, label: "x".repeat(120), value: "secret" }]).valid).toBe(true);
    expect(validateSendDraft("fields", "", [{ concealed: true, label: `${"x".repeat(119)}€`, value: "secret" }]).message).toContain("labels");
  });

  it("counts optional instructions inside the 32-item request schema", () => {
    const fields = Array.from({ length: 31 }, (_, index) => ({ help: "", label: `Field ${index + 1}` }));
    expect(validateRequestDraft("Title", "Instructions", fields).valid).toBe(true);
    expect(validateRequestDraft("Title", "Instructions", [...fields, { help: "", label: "Overflow" }]).message).toContain("including instructions");
    expect(validateRequestDraft(`${"x".repeat(119)}€`, "", fields).message).toContain("title");
  });

  it("blocks missing and oversized request answers before sealing", () => {
    const fields: readonly RequestSchemaField[] = [{ help: "", id: "field001", label: "API key", required: true, type: "secret" }];
    expect(validateRequestAnswers(fields, {}).message).toContain("API key");
    expect(validateRequestAnswers(fields, { field001: "x".repeat(262_144) }).valid).toBe(true);
    expect(validateRequestAnswers(fields, { field001: `${"x".repeat(262_143)}€` }).message).toContain("262144");
  });
});
