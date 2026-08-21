import { describe, expect, test } from "vitest";
import boundaries from "../../../vectors/v1/boundaries.json";
import bundleVectors from "../../../vectors/v1/bundles.json";
import encoding from "../../../vectors/v1/encoding.json";
import envelopeVectors from "../../../vectors/v1/envelopes.json";
import jcsVectors from "../../../vectors/v1/jcs.json";
import keyVectors from "../../../vectors/v1/key-schedules.json";
import negativeVectors from "../../../vectors/v1/negative.json";
import serverVectors from "../../../vectors/v1/server-tags.json";
import {
  decodeBase64Url,
  decodeBundle,
  decodeRandomFactor,
  deriveRandomFactor,
  decodeRequestResponsePayload,
  decodeRequestSchemaPayload,
  decodeSendPayload,
  decryptRequestSchemaEnvelope,
  decryptSendEnvelope,
  deriveCapabilityTag,
  deriveCreatePermitKeys,
  deriveCreatePermitSeed,
  deriveHpkeKeyPair,
  derivePassphraseFactor,
  deriveRateLimitTag,
  deriveRequestOwnerKeys,
  deriveRequestWriteKeys,
  deriveSendKeys,
  encodeBase64Url,
  encodeBundle,
  encodePaddedPlaintext,
  encodeRandomFactor,
  encryptSendEnvelope,
  openRequestResponse,
  parseKxe1Header,
  parseKxr1Header,
  receiptBase64Url,
  receiptDisplay,
  sealRequestResponse,
  selectBucketLength,
  sha256,
  strictUtf8,
  type EncryptSendOptions,
  utf8
} from "./index.js";
import { encryptRequestSchemaEnvelopeWithTestNonce, encryptSendEnvelopeWithTestNonce } from "./kxe1.js";
import { sealRequestResponseWithTestEntropy } from "./kxr1.js";

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

function pattern(offset: number, length: number): Uint8Array<ArrayBuffer> {
  return Uint8Array.from({ length }, (_, index) => (offset + index) & 0xff);
}

function payloadJcs(id: string): string {
  const fixture = jcsVectors.payloads.find((candidate) => candidate.id === id);
  if (fixture === undefined) throw new Error(`missing payload fixture ${id}`);
  return fixture.jcs;
}

describe("external encodings", () => {
  test("matches every base64url and Crockford vector", () => {
    for (const fixture of encoding.base64url) {
      expect(encodeBase64Url(fromHex(fixture.bytesHex))).toBe(fixture.canonical);
      expect(hex(decodeBase64Url(fixture.canonical))).toBe(fixture.bytesHex);
    }
    const secret = fromHex(encoding.crockfordBase32.bytesHex);
    expect(secret).toHaveLength(encoding.crockfordBase32.decodedLength);
    expect(encodeRandomFactor(secret)).toBe(encoding.crockfordBase32.canonicalDisplay);
    expect(hex(decodeRandomFactor(encoding.crockfordBase32.acceptedAliasDisplay))).toBe(hex(secret));
    for (const accepted of encoding.crockfordBase32.acceptedHyphenVariants) {
      expect(hex(decodeRandomFactor(accepted))).toBe(hex(secret));
    }
  });

  test("expands the transmitted second key into the 32-byte schedule factor", async () => {
    const secret = fromHex(encoding.crockfordBase32.bytesHex);
    const factor = await deriveRandomFactor(secret);
    expect(factor).toHaveLength(32);
    expect(hex(factor)).toBe(encoding.crockfordBase32.expansion.factorHex);
    expect(hex(await deriveRandomFactor(decodeRandomFactor(encoding.crockfordBase32.canonicalDisplay)))).toBe(encoding.crockfordBase32.expansion.factorHex);
    await expect(deriveRandomFactor(new Uint8Array(32))).rejects.toMatchObject({ code: "invalid_random_factor" });
  });

  test("rejects every malformed external encoding vector", () => {
    for (const fixture of negativeVectors.malformedExternalEncodings) {
      const decode = fixture.kind === "base64url" ? decodeBase64Url : decodeRandomFactor;
      expect(() => decode(fixture.value), fixture.id).toThrow();
    }
  });
});

describe("factor and key schedules", () => {
  test("matches the static Argon2id vector", async () => {
    const fixture = keyVectors.argon2id;
    expect(hex(await derivePassphraseFactor(strictUtf8(fromHex(fixture.passwordUtf8Hex)), fromHex(fixture.saltHex)))).toBe(fixture.outputHex);
  }, 120_000);

  test("matches every send and request schedule", async () => {
    const sendSeed = fromHex(keyVectors.sendSeedHex);
    const manageSeed = fromHex(keyVectors.manageSeedHex);
    const writeSeed = fromHex(keyVectors.writeSeedHex);
    const ownerSeed = fromHex(keyVectors.ownerSeedHex);
    for (const fixture of keyVectors.send) {
      if (fixture.factorMode !== 0 && fixture.factorMode !== 1 && fixture.factorMode !== 2) throw new Error("bad vector mode");
      const keys = await deriveSendKeys(sendSeed, manageSeed, fixture.factorMode, fromHex(fixture.factorHex));
      expect(encodeBase64Url(keys.locator)).toBe(fixture.locatorBase64url);
      expect(hex(keys.contentKey)).toBe(fixture.contentKeyHex);
      expect(encodeBase64Url(keys.retrieveToken)).toBe(fixture.retrieveTokenBase64url);
      expect(encodeBase64Url(keys.manageToken)).toBe(fixture.manageTokenBase64url);
    }
    for (const fixture of keyVectors.request) {
      if (fixture.factorMode !== 0 && fixture.factorMode !== 1 && fixture.factorMode !== 2) throw new Error("bad vector mode");
      const writeKeys = await deriveRequestWriteKeys(writeSeed, fixture.factorMode, fromHex(fixture.factorHex));
      const ownerKeys = await deriveRequestOwnerKeys(ownerSeed);
      const hpke = await deriveHpkeKeyPair(ownerKeys.hpkeIkm);
      expect(hex(writeKeys.schemaKey)).toBe(fixture.schemaKeyHex);
      expect(encodeBase64Url(writeKeys.writeToken)).toBe(fixture.writeTokenBase64url);
      expect(encodeBase64Url(ownerKeys.ownerToken)).toBe(fixture.ownerTokenBase64url);
      expect(hex(ownerKeys.hpkeIkm)).toBe(fixture.hpkeIkmHex);
      expect(hex(hpke.privateKey)).toBe(fixture.recipientPrivateKeyHex);
      expect(encodeBase64Url(hpke.publicKey)).toBe(fixture.recipientPublicKeyBase64url);
    }
  });
});

describe("KXB1 bundles", () => {
  test("round-trips every frozen bundle byte-for-byte", () => {
    for (const fixture of bundleVectors.bundles) {
      const parsed = decodeBundle(fixture.base64url);
      expect(encodeBundle(parsed), fixture.id).toBe(fixture.base64url);
    }
  });

  test("rejects every malformed bundle container", () => {
    for (const fixture of negativeVectors.malformedContainers.filter((candidate) => candidate.id.startsWith("kxb-"))) {
      expect(() => decodeBundle(fixture.valueBase64url), fixture.id).toThrow();
    }
  });
});

describe("canonical payload boundary", () => {
  test("accepts all four exact JCS payload vectors", () => {
    expect(decodeSendPayload(utf8(payloadJcs("send-text"))).kind).toBe("text");
    expect(decodeSendPayload(utf8(payloadJcs("send-fields"))).kind).toBe("fields");
    const schema = decodeRequestSchemaPayload(utf8(payloadJcs("request-schema")));
    expect(decodeRequestResponsePayload(utf8(payloadJcs("request-response")), schema).kind).toBe("request-response");
  });

  test("rejects invalid canonical JSON and payload fixtures", () => {
    for (const fixture of jcsVectors.invalidJcsAndPayloads) {
      if ("rawJson" in fixture && typeof fixture.rawJson === "string") {
        expect(() => decodeSendPayload(utf8(fixture.rawJson)), fixture.id).toThrow();
      } else if ("utf8Hex" in fixture && typeof fixture.utf8Hex === "string") {
        expect(() => decodeSendPayload(fromHex(fixture.utf8Hex)), fixture.id).toThrow();
      } else {
        const bytes = utf8(JSON.stringify(fixture.object));
        if (fixture.object.kind === "request-schema") {
          expect(() => decodeRequestSchemaPayload(bytes), fixture.id).toThrow();
        } else if (fixture.object.kind === "request-response") {
          if ("expectedSchema" in fixture) {
            const trusted = decodeRequestSchemaPayload(utf8(JSON.stringify(fixture.expectedSchema)));
            expect(() => decodeRequestResponsePayload(bytes, trusted), fixture.id).toThrow();
          } else {
            expect(() => decodeRequestResponsePayload(bytes), fixture.id).toThrow();
          }
        } else {
          expect(() => decodeSendPayload(bytes), fixture.id).toThrow();
        }
      }
    }
  });
});

describe("mandatory padding buckets", () => {
  test("matches every compact boundary digest", async () => {
    for (const fixture of boundaries.cases) {
      if ("error" in fixture) {
        expect(() => selectBucketLength(fixture.payloadLength), fixture.id).toThrow();
        continue;
      }
      const plaintext = encodePaddedPlaintext(
        pattern(fixture.payload.offset, fixture.payloadLength),
        (length) => pattern(fixture.padding.offset, length)
      );
      expect(plaintext.byteLength, fixture.id).toBe(fixture.expectedBucketLength);
      expect(hex(await sha256(plaintext)), fixture.id).toBe(fixture.plaintextSha256Hex);
    }
  });
});

describe("encrypted envelopes", () => {
  test("decrypts all KXE1 vectors and validates their contexts", async () => {
    for (const fixture of envelopeVectors.kxe1) {
      if (fixture.factorMode !== 0 && fixture.factorMode !== 1 && fixture.factorMode !== 2) throw new Error("bad vector mode");
      const envelope = decodeBase64Url(fixture.envelopeBase64url);
      const header = parseKxe1Header(envelope);
      expect(header.clientNotAfter).toBe(fixture.clientNotAfter);
      if (fixture.contentMode === 1) {
        const key = keyVectors.send.find((candidate) => candidate.factorMode === fixture.factorMode);
        if (key === undefined) throw new Error("missing send key");
        const result = await decryptSendEnvelope(envelope, fromHex(key.contentKeyHex), fixture.factorMode, 1800003600, 1800000000);
        expect(result.payload).toEqual(jcsVectors.payloads.find((candidate) => candidate.id === fixture.payloadId)?.object);
        const rebuilt = await encryptSendEnvelopeWithTestNonce({
          clientNotAfter: fixture.clientNotAfter,
          contentKey: fromHex(key.contentKeyHex),
          factorMode: fixture.factorMode,
          maxRetrievals: fixture.maxRetrievals,
          payload: decodeSendPayload(utf8(payloadJcs(fixture.payloadId)))
        }, fromHex(fixture.nonceHex), (length) => pattern(fixture.padding.offset, length));
        expect(encodeBase64Url(rebuilt), fixture.id).toBe(fixture.envelopeBase64url);
      } else {
        const key = keyVectors.request.find((candidate) => candidate.factorMode === fixture.factorMode);
        if (key === undefined) throw new Error("missing request key");
        const result = await decryptRequestSchemaEnvelope(
          envelope,
          fromHex(key.schemaKeyHex),
          fixture.factorMode,
          decodeBase64Url(key.recipientPublicKeyBase64url),
          1800003600,
          1800000000
        );
        expect(result.payload).toEqual(jcsVectors.payloads.find((candidate) => candidate.id === fixture.payloadId)?.object);
        const rebuilt = await encryptRequestSchemaEnvelopeWithTestNonce({
          clientNotAfter: fixture.clientNotAfter,
          factorMode: fixture.factorMode,
          payload: decodeRequestSchemaPayload(utf8(payloadJcs(fixture.payloadId))),
          schemaKey: fromHex(key.schemaKeyHex)
        }, fromHex(fixture.nonceHex), (length) => pattern(fixture.padding.offset, length));
        expect(encodeBase64Url(rebuilt), fixture.id).toBe(fixture.envelopeBase64url);
      }
    }
  });

  test("opens KXR1 and matches receipt vectors", async () => {
    const fixture = envelopeVectors.kxr1;
    const envelope = decodeBase64Url(fixture.envelopeBase64url);
    expect(parseKxr1Header(envelope).ciphertextLength).toBe(fixture.ciphertextLength);
    const opened = await openRequestResponse({
      envelope,
      expectedClientNotAfter: fixture.clientNotAfter,
      hpkeIkm: fromHex(keyVectors.request[0]?.hpkeIkmHex ?? ""),
      nowSeconds: 1800000000,
      requestLocator: fromHex(keyVectors.requestLocatorHex),
      serverExpiresAt: 1800003600
    });
    expect(opened.payload).toEqual(jcsVectors.payloads.find((candidate) => candidate.id === "request-response")?.object);
    expect(await receiptBase64Url(envelope)).toBe(fixture.receiptBase64url);
    expect(await receiptDisplay(envelope)).toBe(fixture.receiptDisplay);

    const response = decodeRequestResponsePayload(utf8(payloadJcs("request-response")));
    const rebuilt = await sealRequestResponseWithTestEntropy({
      expectedClientNotAfter: fixture.clientNotAfter,
      payload: response,
      recipientPublicKey: decodeBase64Url(keyVectors.request[0]?.recipientPublicKeyBase64url ?? ""),
      requestLocator: fromHex(keyVectors.requestLocatorHex),
      schemaDigest: fromHex(fixture.schemaDigestHex)
    }, fromHex(fixture.hpkeEphemeralIkmHex), (length) => pattern(fixture.padding.offset, length));
    expect(encodeBase64Url(rebuilt)).toBe(fixture.envelopeBase64url);
  });

  test("round-trips a fresh KXR1 context and rejects authenticated mismatches", async () => {
    const fixture = envelopeVectors.kxr1;
    const hpkeIkm = fromHex(keyVectors.request[0]?.hpkeIkmHex ?? "");
    const locator = fromHex(keyVectors.requestLocatorHex);
    const response = decodeRequestResponsePayload(utf8(payloadJcs("request-response")));
    const envelope = await sealRequestResponse({
      expectedClientNotAfter: fixture.clientNotAfter,
      payload: response,
      recipientPublicKey: decodeBase64Url(keyVectors.request[0]?.recipientPublicKeyBase64url ?? ""),
      requestLocator: locator,
      schemaDigest: fromHex(fixture.schemaDigestHex)
    });
    const opened = await openRequestResponse({
      envelope,
      expectedClientNotAfter: fixture.clientNotAfter,
      hpkeIkm,
      nowSeconds: 1800000000,
      requestLocator: locator,
      serverExpiresAt: 1800003600
    });
    expect(opened.payload).toEqual(response);

    const tamperedAad = envelope.slice();
    tamperedAad[16] = (tamperedAad[16] ?? 0) ^ 1;
    const tamperedCiphertext = envelope.slice();
    tamperedCiphertext[tamperedCiphertext.length - 1] = (tamperedCiphertext[tamperedCiphertext.length - 1] ?? 0) ^ 1;
    const wrongLocator = locator.slice();
    wrongLocator[0] = (wrongLocator[0] ?? 0) ^ 1;
    const wrongKey = hpkeIkm.slice();
    wrongKey[0] = (wrongKey[0] ?? 0) ^ 1;
    const base = {
      expectedClientNotAfter: fixture.clientNotAfter,
      hpkeIkm,
      nowSeconds: 1800000000,
      requestLocator: locator,
      serverExpiresAt: 1800003600
    };
    await expect(openRequestResponse({ ...base, envelope: tamperedAad })).rejects.toThrow();
    await expect(openRequestResponse({ ...base, envelope: tamperedCiphertext })).rejects.toThrow();
    await expect(openRequestResponse({ ...base, envelope, requestLocator: wrongLocator })).rejects.toThrow();
    await expect(openRequestResponse({ ...base, envelope, hpkeIkm: wrongKey })).rejects.toThrow();
    await expect(openRequestResponse({ ...base, envelope, expectedClientNotAfter: fixture.clientNotAfter + 1 })).rejects.toMatchObject({ code: "context_mismatch" });
  });

  test("rejects invalid timestamps and accepts the maximum safe boundary", async () => {
    const sendFixture = envelopeVectors.kxe1[0];
    if (sendFixture === undefined) throw new Error("missing send envelope");
    const sendEnvelope = decodeBase64Url(sendFixture.envelopeBase64url);
    const sendKey = fromHex(keyVectors.send[0]?.contentKeyHex ?? "");
    for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, -1, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(decryptSendEnvelope(sendEnvelope, sendKey, 0, invalid, 0)).rejects.toMatchObject({ code: "invalid_timestamp" });
      await expect(decryptSendEnvelope(sendEnvelope, sendKey, 0, 1800003600, invalid)).rejects.toMatchObject({ code: "invalid_timestamp" });
      await expect(encryptSendEnvelope({
        clientNotAfter: invalid,
        contentKey: sendKey,
        factorMode: 0,
        maxRetrievals: 1,
        payload: decodeSendPayload(utf8(payloadJcs("send-text")))
      })).rejects.toMatchObject({ code: "invalid_timestamp" });
    }
    await expect(decryptSendEnvelope(
      sendEnvelope, sendKey, 0, Number.MAX_SAFE_INTEGER, 1800000000
    )).resolves.toBeDefined();
    await expect(decryptSendEnvelope(
      sendEnvelope, sendKey, 0, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER
    )).rejects.toMatchObject({ code: "expired" });

    const responseEnvelope = decodeBase64Url(envelopeVectors.kxr1.envelopeBase64url);
    const responsePayload = decodeRequestResponsePayload(utf8(payloadJcs("request-response")));
    const sealBase = {
      payload: responsePayload,
      recipientPublicKey: decodeBase64Url(keyVectors.request[0]?.recipientPublicKeyBase64url ?? ""),
      requestLocator: fromHex(keyVectors.requestLocatorHex),
      schemaDigest: fromHex(envelopeVectors.kxr1.schemaDigestHex)
    };
    const responseBase = {
      envelope: responseEnvelope,
      expectedClientNotAfter: envelopeVectors.kxr1.clientNotAfter,
      hpkeIkm: fromHex(keyVectors.request[0]?.hpkeIkmHex ?? ""),
      nowSeconds: 1800000000,
      requestLocator: fromHex(keyVectors.requestLocatorHex),
      serverExpiresAt: 1800003600
    };
    for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, -1, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(sealRequestResponse({ ...sealBase, expectedClientNotAfter: invalid })).rejects.toMatchObject({ code: "invalid_timestamp" });
      await expect(openRequestResponse({ ...responseBase, expectedClientNotAfter: invalid })).rejects.toMatchObject({ code: "invalid_timestamp" });
      await expect(openRequestResponse({ ...responseBase, nowSeconds: invalid })).rejects.toMatchObject({ code: "invalid_timestamp" });
      await expect(openRequestResponse({ ...responseBase, serverExpiresAt: invalid })).rejects.toMatchObject({ code: "invalid_timestamp" });
    }
    await expect(openRequestResponse({ ...responseBase, serverExpiresAt: Number.MAX_SAFE_INTEGER })).resolves.toBeDefined();
    const maximumEnvelope = await sealRequestResponse({ ...sealBase, expectedClientNotAfter: Number.MAX_SAFE_INTEGER });
    expect(parseKxr1Header(maximumEnvelope).clientNotAfter).toBe(Number.MAX_SAFE_INTEGER);
    await expect(openRequestResponse({
      ...responseBase,
      envelope: maximumEnvelope,
      expectedClientNotAfter: Number.MAX_SAFE_INTEGER,
      serverExpiresAt: Number.MAX_SAFE_INTEGER
    })).resolves.toBeDefined();
  });

  test("production KXE1 encryption ignores caller nonce-shaped data", async () => {
    const suppliedNonce = new Uint8Array(12);
    const optionsWithExtraneousNonce: EncryptSendOptions & { readonly nonce: Uint8Array } = {
      clientNotAfter: 1800003600,
      contentKey: fromHex(keyVectors.send[0]?.contentKeyHex ?? ""),
      factorMode: 0,
      maxRetrievals: 1,
      nonce: suppliedNonce,
      payload: decodeSendPayload(utf8(payloadJcs("send-text")))
    };
    const first = parseKxe1Header(await encryptSendEnvelope(optionsWithExtraneousNonce));
    const second = parseKxe1Header(await encryptSendEnvelope(optionsWithExtraneousNonce));
    expect(first.nonce).not.toEqual(suppliedNonce);
    expect(second.nonce).not.toEqual(suppliedNonce);
    expect(second.nonce).not.toEqual(first.nonce);
  });

  test("rejects every malformed envelope container", async () => {
    for (const fixture of negativeVectors.malformedContainers) {
      if (fixture.id.startsWith("kxe-")) {
        const envelope = decodeBase64Url(fixture.valueBase64url);
        let header;
        try {
          header = parseKxe1Header(envelope);
        } catch {
          continue;
        }
        if (header.contentMode === 1) {
          await expect(decryptSendEnvelope(
            envelope,
            fromHex(keyVectors.send[0]?.contentKeyHex ?? ""),
            header.factorMode,
            1800003600,
            1800000000
          ), fixture.id).rejects.toThrow();
        } else {
          await expect(decryptRequestSchemaEnvelope(
            envelope,
            fromHex(keyVectors.request[0]?.schemaKeyHex ?? ""),
            header.factorMode,
            decodeBase64Url(keyVectors.request[0]?.recipientPublicKeyBase64url ?? ""),
            1800003600,
            1800000000
          ), fixture.id).rejects.toThrow();
        }
      }
      if (fixture.id.startsWith("kxr-")) expect(() => parseKxr1Header(decodeBase64Url(fixture.valueBase64url)), fixture.id).toThrow();
    }
  });

  test("matches wrong-factor schedules and rejects their decryption", async () => {
    for (const fixture of negativeVectors.wrongFactors) {
      const factor = fromHex(fixture.wrongFactorHex);
      if (fixture.id.startsWith("send-")) {
        const mode = fixture.id === "send-passphrase" ? 1 : 2;
        const keys = await deriveSendKeys(fromHex(keyVectors.sendSeedHex), fromHex(keyVectors.manageSeedHex), mode, factor);
        expect(hex(keys.contentKey)).toBe(fixture.wrongContentKeyHex);
        expect(encodeBase64Url(keys.retrieveToken)).toBe(fixture.wrongTokenBase64url);
        const envelope = envelopeVectors.kxe1.find((candidate) => candidate.id === fixture.id)?.envelopeBase64url;
        if (envelope === undefined) throw new Error("missing wrong-factor envelope");
        await expect(decryptSendEnvelope(
          decodeBase64Url(envelope), keys.contentKey, mode, 1800003600, 1800000000
        ), fixture.id).rejects.toThrow();
      } else {
        const mode = fixture.id === "request-passphrase" ? 1 : 2;
        const keys = await deriveRequestWriteKeys(fromHex(keyVectors.writeSeedHex), mode, factor);
        expect(hex(keys.schemaKey)).toBe(fixture.wrongSchemaKeyHex);
        expect(encodeBase64Url(keys.writeToken)).toBe(fixture.wrongTokenBase64url);
        const envelopeId = mode === 1 ? "request-schema-passphrase" : "request-schema-random-factor";
        const envelope = envelopeVectors.kxe1.find((candidate) => candidate.id === envelopeId)?.envelopeBase64url;
        if (envelope === undefined) throw new Error("missing wrong-factor envelope");
        await expect(decryptRequestSchemaEnvelope(
          decodeBase64Url(envelope),
          keys.schemaKey,
          mode,
          decodeBase64Url(keyVectors.request[0]?.recipientPublicKeyBase64url ?? ""),
          1800003600,
          1800000000
        ), fixture.id).rejects.toThrow();
      }
    }
  });

  test("rejects envelopes at the wrong container endpoint", () => {
    expect(() => parseKxe1Header(decodeBase64Url(envelopeVectors.kxr1.envelopeBase64url))).toThrow();
    expect(() => parseKxr1Header(decodeBase64Url(envelopeVectors.kxe1[0]?.envelopeBase64url ?? ""))).toThrow();
  });

  test("rejects every cross-container context mismatch", async () => {
    const sendEnvelope = decodeBase64Url(envelopeVectors.kxe1.find((candidate) => candidate.id === "send-none")?.envelopeBase64url ?? "");
    await expect(decryptSendEnvelope(
      sendEnvelope,
      fromHex(keyVectors.send[0]?.contentKeyHex ?? ""),
      1,
      1800003600,
      1800000000
    )).rejects.toThrow();

    const schemaEnvelope = decodeBase64Url(envelopeVectors.kxe1.find((candidate) => candidate.id === "request-schema-none")?.envelopeBase64url ?? "");
    const mismatchedWrite = negativeVectors.crossContainerMismatches.find((candidate) => candidate.id === "write-public-key-vs-schema");
    if (mismatchedWrite === undefined || !("valueBase64url" in mismatchedWrite)) throw new Error("missing public-key mismatch");
    const writeBundle = decodeBundle(mismatchedWrite.valueBase64url);
    if (writeBundle.kind !== 3) throw new Error("wrong mismatch bundle kind");
    await expect(decryptRequestSchemaEnvelope(
      schemaEnvelope,
      fromHex(keyVectors.request[0]?.schemaKeyHex ?? ""),
      0,
      writeBundle.recipientPublicKey,
      1800003600,
      1800000000
    )).rejects.toThrow();

    for (const id of ["response-schema-digest-vs-schema", "response-expiry-vs-schema"]) {
      const fixture = negativeVectors.crossContainerMismatches.find((candidate) => candidate.id === id);
      if (fixture === undefined || !("valueBase64url" in fixture)) throw new Error(`missing ${id}`);
      await expect(openRequestResponse({
        envelope: decodeBase64Url(fixture.valueBase64url),
        expectedClientNotAfter: envelopeVectors.kxr1.clientNotAfter,
        hpkeIkm: fromHex(keyVectors.request[0]?.hpkeIkmHex ?? ""),
        nowSeconds: 1800000000,
        requestLocator: fromHex(keyVectors.requestLocatorHex),
        serverExpiresAt: 1800003601
      }), id).rejects.toThrow();
    }
  });
});

describe("server-side domain-separated tags", () => {
  test("matches every capability and rate-limit fixture", async () => {
    for (const fixture of serverVectors.capabilityTags) {
      if (
        (fixture.resourceKind !== 1 && fixture.resourceKind !== 2 && fixture.resourceKind !== 3) ||
        (fixture.capabilityKind !== 1 && fixture.capabilityKind !== 2 && fixture.capabilityKind !== 3)
      ) throw new Error("bad tag fixture");
      const tag = await deriveCapabilityTag(
        fromHex(serverVectors.serverKeyHex),
        fixture.resourceKind,
        fixture.capabilityKind,
        decodeBase64Url(fixture.locatorBase64url),
        decodeBase64Url(fixture.tokenBase64url)
      );
      expect(hex(tag), fixture.id).toBe(fixture.tagHex);
    }
    for (const fixture of serverVectors.rateLimitTags) {
      if (fixture.resourceKind !== 1 && fixture.resourceKind !== 2 && fixture.resourceKind !== 3) throw new Error("bad rate fixture");
      const tag = await deriveRateLimitTag(
        fromHex(serverVectors.rateLimitKeyHex),
        fixture.resourceKind,
        decodeBase64Url(fixture.locatorBase64url)
      );
      expect(encodeBase64Url(tag), fixture.id).toBe(fixture.tagBase64url);
    }
    const permit = serverVectors.createPermit;
    const seed = await deriveCreatePermitSeed(fromHex(permit.issuanceKeyHex), fromHex(permit.requestIdHex));
    expect(hex(seed)).toBe(permit.permitSeedHex);
    const keys = await deriveCreatePermitKeys(seed);
    expect(encodeBase64Url(keys.locator)).toBe(permit.permitLocatorBase64url);
    expect(encodeBase64Url(keys.token)).toBe(permit.permitTokenBase64url);
  });
});
