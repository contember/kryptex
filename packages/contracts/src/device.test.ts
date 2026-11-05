import { describe, expect, test } from "vitest";
import {
  parseApiErrorResponse,
  parseDeviceAccessRequest,
  parseDevicePairingClaimRequest,
  parseDevicePairingClaimResponse,
  parseDevicePairingRedeemResponse,
  parseDevicePairingStartRequest,
  parseDevicePermitRequest,
  parseDevicePermitResponse,
  parseDeviceStatusResponse
} from "./api.js";
import { decodeDeviceLink, encodeDeviceLink } from "./device-link.js";

const locator = "AAAAAAAAAAAAAAAAAAAAAA";
const token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const permitSeed = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
const requestId = "550e8400-e29b-41d4-a716-446655440000";

describe("device grant contracts", () => {
  test("accepts only the allowed grant lifetimes", () => {
    for (const maxDays of [1, 7, 30, 90]) {
      expect(parseDevicePairingStartRequest({ deviceLocator: locator, deviceToken: token, maxDays }).maxDays).toBe(maxDays);
    }
    for (const maxDays of [0, 2, 31, 365, 30.5]) {
      expect(() => parseDevicePairingStartRequest({ deviceLocator: locator, deviceToken: token, maxDays })).toThrow();
    }
  });

  test("distinguishes the two claim choices and rejects mixtures", () => {
    expect(parseDevicePairingClaimRequest({ scope: "transfer" })).toEqual({ scope: "transfer" });
    expect(parseDevicePairingClaimRequest({ days: 7, manageToken: token, scope: "device" })).toEqual({ days: 7, manageToken: token, scope: "device" });
    expect(() => parseDevicePairingClaimRequest({ scope: "device" })).toThrow();
    expect(() => parseDevicePairingClaimRequest({ days: 7, manageToken: token, scope: "transfer" })).toThrow();
    expect(() => parseDevicePairingClaimRequest({ days: 7, scope: "transfer" })).toThrow();
    expect(parseDevicePairingClaimResponse({ deviceExpiresAt: 1, deviceLocator: locator, scope: "device" }).scope).toBe("device");
  });

  test("parses each redeem outcome and keeps version 2 permits for a single transfer", () => {
    expect(parseDevicePairingRedeemResponse({ pairingExpiresAt: 5, state: "pending" })).toEqual({ pairingExpiresAt: 5, state: "pending" });
    expect(parseDevicePairingRedeemResponse({ deviceExpiresAt: 5, state: "device" })).toEqual({ deviceExpiresAt: 5, state: "device" });
    expect(parseDevicePairingRedeemResponse({ permit: `v2.${permitSeed}`, permitExpiresAt: 5, serverTime: 1, state: "transfer" }).state).toBe("transfer");
    expect(() => parseDevicePairingRedeemResponse({ permit: `v3.${permitSeed}`, permitExpiresAt: 5, serverTime: 1, state: "transfer" })).toThrow();
    expect(() => parseDevicePairingRedeemResponse({ deviceExpiresAt: 5, state: "pending" })).toThrow();
  });

  test("requires a version 3 permit from minting", () => {
    expect(parseDevicePermitRequest({ deviceLocator: locator, deviceToken: token, requestId }).requestId).toBe(requestId);
    expect(parseDevicePermitResponse({ permit: `v3.${permitSeed}`, permitExpiresAt: 2, serverTime: 1 }).permit).toBe(`v3.${permitSeed}`);
    expect(() => parseDevicePermitResponse({ permit: `v2.${permitSeed}`, permitExpiresAt: 2, serverTime: 1 })).toThrow();
  });

  test("accepts exactly one capability for status and revocation", () => {
    expect(parseDeviceAccessRequest({ deviceLocator: locator, deviceToken: token })).toEqual({ deviceLocator: locator, deviceToken: token });
    expect(parseDeviceAccessRequest({ deviceLocator: locator, manageToken: token })).toEqual({ deviceLocator: locator, manageToken: token });
    expect(() => parseDeviceAccessRequest({ deviceLocator: locator, deviceToken: token, manageToken: token })).toThrow();
    expect(() => parseDeviceAccessRequest({ deviceLocator: locator })).toThrow();
  });

  test("bounds the status counters", () => {
    const hourlyMints = Array.from({ length: 24 }, () => 0);
    expect(parseDeviceStatusResponse({ expiresAt: 9, hourlyMints, quotaRemaining: 50, state: "active" }).quotaRemaining).toBe(50);
    expect(() => parseDeviceStatusResponse({ expiresAt: 9, hourlyMints: hourlyMints.slice(1), quotaRemaining: 50, state: "active" })).toThrow();
    expect(() => parseDeviceStatusResponse({ expiresAt: 9, hourlyMints, quotaRemaining: 51, state: "active" })).toThrow();
    expect(() => parseDeviceStatusResponse({ expiresAt: 9, hourlyMints, quotaRemaining: 1, state: "expired" })).toThrow();
  });

  test("knows the quota error", () => {
    expect(parseApiErrorResponse({ error: "quota_exhausted" })).toEqual({ error: "quota_exhausted" });
  });
});

describe("device management link", () => {
  test("round-trips and rejects other magics, versions, and lengths", () => {
    const link = { deviceLocator: "AQIDBAUGBwgJCgsMDQ4PEA", manageToken: "ERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzA" };
    const encoded = encodeDeviceLink(link);
    expect(decodeDeviceLink(encoded)).toEqual(link);
    expect(encoded.startsWith("S1hEMQE")).toBe(true);
    const bytes = Uint8Array.from(atob(encoded.replaceAll("-", "+").replaceAll("_", "/")), (character) => character.charCodeAt(0));
    const reencode = (value: Uint8Array): string => btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    const wrongVersion = bytes.slice();
    wrongVersion[4] = 2;
    expect(() => decodeDeviceLink(reencode(wrongVersion))).toThrow();
    const wrongMagic = bytes.slice();
    wrongMagic[0] = 0x4a;
    expect(() => decodeDeviceLink(reencode(wrongMagic))).toThrow();
    expect(() => decodeDeviceLink(reencode(bytes.subarray(0, 52)))).toThrow();
  });
});
