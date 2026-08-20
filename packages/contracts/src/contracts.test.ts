import { describe, expect, test } from "vitest";
import jcsVectors from "../../../vectors/v1/jcs.json";
import {
  parseCreatePermitRequestJson,
  parseRequestSubmitResponse,
  parseSendRetrieveRequest
} from "./api.js";
import {
  parseRequestResponsePayload,
  parseRequestSchemaPayload,
  parseSendPayload,
  serializeCanonicalPayload
} from "./payloads.js";

function vectorObject(id: string): unknown {
  return jcsVectors.payloads.find((candidate) => candidate.id === id)?.object;
}

function vectorCanonicalJson(id: string): string | undefined {
  return jcsVectors.payloads.find((candidate) => candidate.id === id)?.jcs;
}

describe("canonical payload contracts", () => {
  test("matches every JCS payload vector", () => {
    const sendText = parseSendPayload(vectorObject("send-text"));
    const sendFields = parseSendPayload(vectorObject("send-fields"));
    const schema = parseRequestSchemaPayload(vectorObject("request-schema"));
    const response = parseRequestResponsePayload(vectorObject("request-response"), schema);

    expect(serializeCanonicalPayload(sendText)).toBe(vectorCanonicalJson("send-text"));
    expect(serializeCanonicalPayload(sendFields)).toBe(vectorCanonicalJson("send-fields"));
    expect(serializeCanonicalPayload(schema)).toBe(vectorCanonicalJson("request-schema"));
    expect(serializeCanonicalPayload(response)).toBe(vectorCanonicalJson("request-response"));
  });

  test("rejects extra fields and invalid answer ordering", () => {
    expect(() => parseSendPayload({ extra: true, kind: "text", text: "secret" })).toThrow();
    expect(() =>
      parseRequestResponsePayload({
        answers: [
          { id: "context1", value: "second" },
          { id: "apitoken", value: "first" }
        ],
        kind: "request-response",
        schema: vectorObject("request-schema")
      })
    ).toThrow();
  });

  test("rejects invalid nested schema and payload invariants", () => {
    expect(() =>
      parseRequestSchemaPayload({
        fields: [
          { help: "", id: "duplicate", label: "First", required: false, type: "short" },
          { help: "", id: "duplicate", label: "Second", required: false, type: "secret" }
        ],
        kind: "request-schema",
        recipientPublicKey: "jwp2f1_qwgefetCrLPDupxPHHk-nBnS2K1nuNMmYgSY",
        title: "Duplicate IDs"
      })
    ).toThrow();
    expect(() =>
      parseRequestSchemaPayload({
        fields: [{ help: "", id: "notice001", label: "Notice", required: true, type: "instruction" }],
        kind: "request-schema",
        recipientPublicKey: "jwp2f1_qwgefetCrLPDupxPHHk-nBnS2K1nuNMmYgSY",
        title: "Required instruction"
      })
    ).toThrow();
    expect(() => parseSendPayload({ kind: "text", text: "\ud800" })).toThrow();
    expect(() =>
      parseSendPayload({ fields: [{ concealed: true, extra: false, label: "Key", value: "secret" }], kind: "fields" })
    ).toThrow();
  });

  test("rejects empty required answers and a substituted trusted schema", () => {
    const schema = parseRequestSchemaPayload(vectorObject("request-schema"));
    const response = vectorObject("request-response");
    expect(() =>
      parseRequestResponsePayload(
        {
          answers: [
            { id: "apitoken", value: "" },
            { id: "context1", value: "" }
          ],
          kind: "request-response",
          schema
        },
        schema
      )
    ).toThrow();
    const substituted = parseRequestSchemaPayload({
      fields: schema.fields,
      kind: "request-schema",
      recipientPublicKey: schema.recipientPublicKey,
      title: "Substituted title"
    });
    expect(() => parseRequestResponsePayload(response, substituted)).toThrow();
  });
});

describe("HTTP API contracts", () => {
  test("rejects duplicate JSON keys before object parsing", () => {
    expect(() =>
      parseCreatePermitRequestJson(
        '{"requestId":"550e8400-e29b-41d4-a716-446655440000","requestId":"550e8400-e29b-41d4-a716-446655440000","turnstileResponse":"token"}'
      )
    ).toThrow(/duplicate/u);
  });

  test("accepts canonical locator and token lengths", () => {
    expect(
      parseSendRetrieveRequest({
        locator: "cHFyc3R1dnd4eXp7fH1-fw",
        retrieveToken: "XjRiA1HoeeUaoQOPidcGWU_2lcqoMPhmtt3-exx8hPo"
      })
    ).toEqual({
      locator: "cHFyc3R1dnd4eXp7fH1-fw",
      retrieveToken: "XjRiA1HoeeUaoQOPidcGWU_2lcqoMPhmtt3-exx8hPo"
    });
  });

  test("rejects non-canonical base64url and extra response fields", () => {
    expect(() =>
      parseSendRetrieveRequest({
        locator: "cHFyc3R1dnd4eXp7fH1-fw=",
        retrieveToken: "XjRiA1HoeeUaoQOPidcGWU_2lcqoMPhmtt3-exx8hPo"
      })
    ).toThrow();
    expect(() =>
      parseRequestSubmitResponse({
        extra: true,
        receipt: "XjRiA1HoeeUaoQOPidcGWU_2lcqoMPhmtt3-exx8hPo"
      })
    ).toThrow();
  });
});
