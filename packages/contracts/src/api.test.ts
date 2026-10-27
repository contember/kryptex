import { describe, expect, test } from "vitest";
import envelopeVectors from "../../../vectors/v1/envelopes.json";
import {
  parseApiErrorResponse,
  parseApiJsonText,
  parseCreatePermitRequest,
  parseCreatePermitResponse,
  parseCreatePermitStatusResponse,
  parseCreateResourceResponse,
  decodeUserCode,
  encodeUserCode,
  normalizeUserCodeInput,
  parseEmptyRequest,
  parsePairingApproveRequest,
  parsePairingApproveResponse,
  parsePairingRedeemRequest,
  parsePairingRedeemResponse,
  parsePairingStartRequest,
  parsePairingStartResponse,
  parseRequestCreateRequest,
  parseRequestOwnerRequest,
  parseRequestPickupMetadata,
  parseRequestSchemaMetadata,
  parseRequestShortenRequest,
  parseRequestStatusResponse,
  parseRequestSubmitRequest,
  parseRequestSubmitResponse,
  parseRequestWriteRequest,
  parseRevokeResponse,
  parseSendCreateRequest,
  parseSendManageRequest,
  parseSendRetrieveMetadata,
  parseSendRetrieveRequest,
  parseSendShortenRequest,
  parseSendStatusResponse,
  parseServerTimeMetadata,
  parseShortenResponse,
  parseStateCheckedMetadata
} from "./api.js";
import { FAILED_ACCESS_SATURATION } from "./protocol.js";

interface ContractCase {
  readonly name: string;
  readonly parse: (value: unknown) => unknown;
  readonly value: object;
}

const locator = "cHFyc3R1dnd4eXp7fH1-fw";
const token = "XjRiA1HoeeUaoQOPidcGWU_2lcqoMPhmtt3-exx8hPo";
const attemptId = "AAECAwQFBgcICQoLDA0ODw";
const sendEnvelope = envelopeVectors.kxe1[0]?.envelopeBase64url ?? "";
const schemaEnvelope = envelopeVectors.kxe1[1]?.envelopeBase64url ?? "";
const responseEnvelope = envelopeVectors.kxr1.envelopeBase64url;
const clientNotAfter = envelopeVectors.kxr1.clientNotAfter;

const requestCases: readonly ContractCase[] = [
  {
    name: "POST /api/v2/create-permits",
    parse: parseCreatePermitRequest,
    value: {
      requestId: "550e8400-e29b-41d4-a716-446655440000",
      turnstileResponse: "turnstile-token"
    }
  },
  { name: "POST /api/v2/create-permits/status", parse: parseEmptyRequest, value: {} },
  { name: "POST /api/v2/create-permits/pairings", parse: parsePairingStartRequest, value: { pollToken: token } },
  {
    name: "POST /api/v2/create-permits/pairings/approve",
    parse: parsePairingApproveRequest,
    value: { requestId: "550e8400-e29b-41d4-a716-446655440000", turnstileResponse: "turnstile-token", userCode: "ABCD-EFGH" }
  },
  { name: "POST /api/v2/create-permits/pairings/redeem", parse: parsePairingRedeemRequest, value: { pollToken: token, userCode: "ABCD-EFGH" } },
  {
    name: "POST /api/v1/sends",
    parse: parseSendCreateRequest,
    value: {
      attemptId,
      clientNotAfter,
      envelope: sendEnvelope,
      locator,
      manageToken: token,
      maxRetrievals: 1,
      retrieveToken: token,
      settleNotAfter: 1800000000,
      ttlSeconds: 3600
    }
  },
  {
    name: "POST /api/v1/sends/retrieve",
    parse: parseSendRetrieveRequest,
    value: { locator, retrieveToken: token }
  },
  { name: "POST /api/v1/sends/status", parse: parseSendManageRequest, value: { locator, manageToken: token } },
  { name: "POST /api/v1/sends/revoke", parse: parseSendManageRequest, value: { locator, manageToken: token } },
  {
    name: "POST /api/v1/sends/shorten",
    parse: parseSendShortenRequest,
    value: { locator, manageToken: token, serverExpiresAt: 1800001800 }
  },
  {
    name: "POST /api/v1/requests",
    parse: parseRequestCreateRequest,
    value: {
      attemptId,
      clientNotAfter,
      envelope: schemaEnvelope,
      locator,
      ownerToken: token,
      settleNotAfter: 1800000000,
      ttlSeconds: 3600,
      writeToken: token
    }
  },
  { name: "POST /api/v1/requests/schema", parse: parseRequestWriteRequest, value: { locator, writeToken: token } },
  {
    name: "POST /api/v1/requests/submit",
    parse: parseRequestSubmitRequest,
    value: { envelope: responseEnvelope, locator, writeToken: token }
  },
  { name: "POST /api/v1/requests/status", parse: parseRequestOwnerRequest, value: { locator, ownerToken: token } },
  { name: "POST /api/v1/requests/pickup", parse: parseRequestOwnerRequest, value: { locator, ownerToken: token } },
  { name: "POST /api/v1/requests/revoke", parse: parseRequestOwnerRequest, value: { locator, ownerToken: token } },
  {
    name: "POST /api/v1/requests/shorten",
    parse: parseRequestShortenRequest,
    value: { locator, ownerToken: token, serverExpiresAt: 1800001800 }
  }
];

const responseCases: readonly ContractCase[] = [
  {
    name: "create permit",
    parse: parseCreatePermitResponse,
    value: { permitExpiresAt: 1800000300, serverTime: 1800000000 }
  },
  {
    name: "create permit status",
    parse: parseCreatePermitStatusResponse,
    value: { permitExpiresAt: 1800000300, serverTime: 1800000000, state: "unused" }
  },
  {
    name: "pairing start",
    parse: parsePairingStartResponse,
    value: { pairingExpiresAt: 1800000600, serverTime: 1800000000, userCode: "ABCD-EFGH" }
  },
  { name: "pairing approve", parse: parsePairingApproveResponse, value: { state: "approved" } },
  { name: "pending pairing redeem", parse: parsePairingRedeemResponse, value: { pairingExpiresAt: 1800000600, state: "pending" } },
  {
    name: "approved pairing redeem",
    parse: parsePairingRedeemResponse,
    value: { permit: `v2.${token}`, permitExpiresAt: 1800001800, serverTime: 1800000000, state: "approved" }
  },
  { name: "send create", parse: parseCreateResourceResponse, value: { serverExpiresAt: 1800003600 } },
  { name: "request create", parse: parseCreateResourceResponse, value: { serverExpiresAt: 1800003600 } },
  {
    name: "send status",
    parse: parseSendStatusResponse,
    value: { failedAccessAttempts: 0, releasedAt: [1800000100], remainingRetrievals: 1, serverExpiresAt: 1800003600, state: "active" }
  },
  { name: "send revoke", parse: parseRevokeResponse, value: { state: "revoked" } },
  { name: "request revoke", parse: parseRevokeResponse, value: { state: "revoked" } },
  { name: "send shorten", parse: parseShortenResponse, value: { serverExpiresAt: 1800001800 } },
  { name: "request shorten", parse: parseShortenResponse, value: { serverExpiresAt: 1800001800 } },
  { name: "request submit", parse: parseRequestSubmitResponse, value: { receipt: token } },
  {
    name: "request status",
    parse: parseRequestStatusResponse,
    value: { serverExpiresAt: 1800003600, state: "submitted" }
  },
  { name: "generic error", parse: parseApiErrorResponse, value: { error: "unavailable" } }
];

describe("all API route bodies", () => {
  test.each(requestCases)("accepts $name", ({ parse, value }) => {
    expect(parse(value)).toBeDefined();
    expect(parseApiJsonText(JSON.stringify(value), parse)).toBeDefined();
  });

  test.each(requestCases)("rejects extra keys for $name", ({ parse, value }) => {
    expect(() => parse({ ...value, unexpected: true })).toThrow();
  });

  test.each(responseCases)("accepts the $name response", ({ parse, value }) => {
    expect(parse(value)).toBeDefined();
    expect(parseApiJsonText(JSON.stringify(value), parse)).toBeDefined();
  });

  test.each(responseCases)("rejects extra keys in the $name response", ({ parse, value }) => {
    expect(() => parse({ ...value, unexpected: true })).toThrow();
  });

  test("rejects duplicate raw JSON keys before route parsing", () => {
    expect(() =>
      parseApiJsonText(`{"locator":"${locator}","locator":"${locator}","retrieveToken":"${token}"}`, parseSendRetrieveRequest)
    ).toThrow(/duplicate/u);
  });

  test("cross-checks create body metadata against clear envelope headers", () => {
    const send = requestCases.find((candidate) => candidate.name === "POST /api/v1/sends");
    const request = requestCases.find((candidate) => candidate.name === "POST /api/v1/requests");
    if (send === undefined || request === undefined) {
      throw new Error("missing create request fixtures");
    }
    expect(() => parseSendCreateRequest({ ...send.value, clientNotAfter: clientNotAfter + 1 })).toThrow();
    expect(() => parseSendCreateRequest({ ...send.value, envelope: schemaEnvelope })).toThrow();
    expect(() => parseRequestCreateRequest({ ...request.value, envelope: sendEnvelope })).toThrow();
  });

  test("rejects malformed lengths, pad bits, TTLs, and states", () => {
    expect(() => parseSendRetrieveRequest({ locator: `${locator}=`, retrieveToken: token })).toThrow();
    expect(() => parseSendRetrieveRequest({ locator: "cHFyc3R1dnd4eXp7fH1-fx", retrieveToken: token })).toThrow();
    expect(() => parseSendRetrieveRequest({ locator, retrieveToken: token.slice(1) })).toThrow();
    const send = requestCases.find((candidate) => candidate.name === "POST /api/v1/sends");
    if (send === undefined) {
      throw new Error("missing send create fixture");
    }
    expect(() => parseSendCreateRequest({ ...send.value, ttlSeconds: 42 })).toThrow();
    expect(() => parseSendStatusResponse({ failedAccessAttempts: 0, releasedAt: [], remainingRetrievals: 1, serverExpiresAt: 1, state: "missing" })).toThrow();
    expect(() => parseRequestStatusResponse({ serverExpiresAt: 1, state: "active" })).toThrow();
  });

  test("bounds the access facts a send status may report", () => {
    const base = { failedAccessAttempts: 0, releasedAt: [], remainingRetrievals: 1, serverExpiresAt: 1800003600, state: "active" };
    expect(parseSendStatusResponse({ ...base, failedAccessAttempts: FAILED_ACCESS_SATURATION }).failedAccessAttempts).toBe(FAILED_ACCESS_SATURATION);
    expect(() => parseSendStatusResponse({ ...base, failedAccessAttempts: FAILED_ACCESS_SATURATION + 1 })).toThrow();
    expect(() => parseSendStatusResponse({ ...base, failedAccessAttempts: -1 })).toThrow();
    expect(() => parseSendStatusResponse({ ...base, releasedAt: Array.from({ length: 11 }, () => 1800000100) })).toThrow();
    expect(() => parseSendStatusResponse({ ...base, releasedAt: [1800000100.5] })).toThrow();
    expect(() => parseSendStatusResponse({ ...base, releasedAt: "1800000100" })).toThrow();
  });
});

describe("pairing user codes", () => {
  test("round-trips every byte value through the canonical form", () => {
    for (let value = 0; value < 256; value += 1) {
      const bytes = Uint8Array.of(value, 255 - value, value ^ 0x5a, 0, 255);
      expect(decodeUserCode(encodeUserCode(bytes))).toEqual(bytes);
    }
    expect(encodeUserCode(new Uint8Array(5))).toBe("0000-0000");
    expect(encodeUserCode(Uint8Array.of(255, 255, 255, 255, 255))).toBe("ZZZZ-ZZZZ");
  });

  test("normalizes typed input with the second-key rules", () => {
    expect(normalizeUserCodeInput("abcd-efgh")).toBe("ABCD-EFGH");
    expect(normalizeUserCodeInput("ABCDEFGH")).toBe("ABCD-EFGH");
    expect(normalizeUserCodeInput("oIL0-1234")).toBe("0110-1234");
    expect(normalizeUserCodeInput("ABCD-EFGU")).toBeNull();
    expect(normalizeUserCodeInput("ABC-DEFGH")).toBeNull();
    expect(normalizeUserCodeInput("ABCD EFGH")).toBeNull();
    expect(normalizeUserCodeInput("ABCD-EFG")).toBeNull();
  });

  test("accepts only canonical codes and version 2 permits on the wire", () => {
    expect(() => parsePairingRedeemRequest({ pollToken: token, userCode: "abcd-efgh" })).toThrow();
    expect(() => parsePairingRedeemRequest({ pollToken: token, userCode: "ABCDEFGH" })).toThrow();
    expect(() => parsePairingRedeemRequest({ pollToken: token, userCode: "ABCD-EFGI" })).toThrow();
    expect(() => parsePairingRedeemResponse({ permit: `v1.${token}`, permitExpiresAt: 1, serverTime: 1, state: "approved" })).toThrow();
    expect(() => parsePairingRedeemResponse({ pairingExpiresAt: 1, state: "approved" })).toThrow();
  });
});

describe("response metadata headers", () => {
  test("parses every specified metadata response", () => {
    const headers = new Headers({
      "Kryptex-Receipt": token,
      "Kryptex-Remaining-Releases": "9",
      "Kryptex-Server-Expires-At": "1800003600",
      "Kryptex-Server-Time": "1800000000",
      "Kryptex-State-Checked-At": "1800000001"
    });
    expect(parseSendRetrieveMetadata(headers)).toEqual({ remainingReleases: 9, serverExpiresAt: 1800003600 });
    expect(parseRequestSchemaMetadata(headers)).toEqual({ serverExpiresAt: 1800003600 });
    expect(parseRequestPickupMetadata(headers)).toEqual({ receipt: token, serverExpiresAt: 1800003600 });
    expect(parseServerTimeMetadata(headers)).toEqual({ serverTime: 1800000000 });
    expect(parseStateCheckedMetadata(headers)).toEqual({ stateCheckedAt: 1800000001 });
  });

  test.each([
    ["Kryptex-Server-Time", "-1", parseServerTimeMetadata],
    ["Kryptex-Server-Time", "01", parseServerTimeMetadata],
    ["Kryptex-Server-Time", "9007199254740992", parseServerTimeMetadata],
    ["Kryptex-State-Checked-At", "1.5", parseStateCheckedMetadata],
    ["Kryptex-State-Checked-At", "", parseStateCheckedMetadata]
  ])("rejects invalid %s value %s", (name, value, parse) => {
    expect(() => parse(new Headers({ [name]: value }))).toThrow();
  });
});
