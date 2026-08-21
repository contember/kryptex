import {
  createCipheriv,
  createHash,
  createHmac,
} from "node:crypto";
import {
  Aes256Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import canonicalize from "canonicalize";
import { argon2id } from "hash-wasm";

const utf8Encoder = new TextEncoder();
const bucketLength = 4096;
const clientNotAfter = 1800003600;
const serverExpiresAt = 1800003000;
const zero32 = new Uint8Array(32);

function utf8(value) {
  return utf8Encoder.encode(value);
}

function hex(value) {
  return Buffer.from(value).toString("hex");
}

function fromHex(value) {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function concat(...values) {
  const length = values.reduce((total, value) => total + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function sequence(start, length) {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function pattern(offset, length) {
  return Uint8Array.from({ length }, (_, index) => (offset + index) & 0xff);
}

function u16(value) {
  const output = Buffer.alloc(2);
  output.writeUInt16BE(value);
  return new Uint8Array(output);
}

function u32(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return new Uint8Array(output);
}

function u64(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return new Uint8Array(output);
}

function sha256(value) {
  return new Uint8Array(createHash("sha256").update(value).digest());
}

function hmac(key, value) {
  return new Uint8Array(createHmac("sha256", key).update(value).digest());
}

function extract(label, ikm) {
  return hmac(sha256(utf8(label)), ikm);
}

function expand(prk, label, length) {
  const info = utf8(label);
  let previous = new Uint8Array();
  let output = new Uint8Array();
  let counter = 1;
  while (output.length < length) {
    previous = hmac(prk, concat(previous, info, Uint8Array.of(counter)));
    output = concat(output, previous);
    counter += 1;
  }
  return output.slice(0, length);
}

function aesGcmEncrypt(key, nonce, aad, plaintext) {
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return concat(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
}

function jcs(value) {
  const output = canonicalize(value);
  if (output === undefined) {
    throw new Error("JCS serialization failed");
  }
  return utf8(output);
}

function paddedPlaintextForBucket(payload, paddingOffset, selectedBucketLength) {
  const remaining = selectedBucketLength - 4 - payload.length;
  if (remaining < 0) {
    throw new Error("Fixture payload does not fit the first bucket");
  }
  return concat(u32(payload.length), payload, pattern(paddingOffset, remaining));
}

function paddedPlaintext(payload, paddingOffset) {
  return paddedPlaintextForBucket(payload, paddingOffset, bucketLength);
}

const base32Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function crockfordEncode(value) {
  let accumulator = 0;
  let bits = 0;
  let output = "";
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += base32Alphabet[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    output += base32Alphabet[(accumulator << (5 - bits)) & 31];
  }
  return [output.slice(0, 5), output.slice(5, 10), output.slice(10, 15), output.slice(15, 20), output.slice(20)].join("-");
}

function kxb(kind, body) {
  return concat(utf8("KXB1"), Uint8Array.of(kind, 1), u16(body.length), body);
}

function kxeHeader(contentMode, factorMode, maxRetrievals, schemaDigest, nonce) {
  return concat(
    utf8("KXE1"),
    Uint8Array.of(1, contentMode, factorMode, 0),
    u64(clientNotAfter),
    u16(maxRetrievals),
    schemaDigest,
    nonce,
  );
}

function mutate(value, offset, replacement) {
  const copy = Uint8Array.from(value);
  copy[offset] = replacement;
  return copy;
}

function sendSchedule(sendSeed, manageSeed, factorMode, factor) {
  const modeName = ["none", "passphrase", "random-factor"][factorMode];
  const locatorPrk = extract("kryptex/v1/send/locator", sendSeed);
  const masterPrk = extract(`kryptex/v1/send/master/${modeName}`, concat(sendSeed, factor));
  const managePrk = extract("kryptex/v1/send/manage-token", manageSeed);
  return {
    factorMode,
    factorModeName: modeName,
    factorHex: hex(factor),
    locatorPrkHex: hex(locatorPrk),
    locatorBase64url: base64url(expand(locatorPrk, "kryptex/v1/send/locator", 16)),
    masterPrkHex: hex(masterPrk),
    contentKeyHex: hex(expand(masterPrk, "kryptex/v1/send/content-key", 32)),
    retrieveTokenBase64url: base64url(expand(masterPrk, "kryptex/v1/send/retrieve-token", 32)),
    managePrkHex: hex(managePrk),
    manageTokenBase64url: base64url(expand(managePrk, "kryptex/v1/send/manage-token", 32)),
  };
}

async function requestSchedule(requestLocator, writeSeed, ownerSeed, factorMode, factor, suite) {
  const modeName = ["none", "passphrase", "random-factor"][factorMode];
  const writePrk = extract(`kryptex/v1/request/write-master/${modeName}`, concat(writeSeed, factor));
  const ownerPrk = extract("kryptex/v1/request/owner-token", ownerSeed);
  const hpkeIkm = expand(ownerPrk, "kryptex/v1/request/hpke-keypair", 32);
  const recipientKeyPair = await suite.kem.deriveKeyPair(hpkeIkm);
  const recipientPublicKey = new Uint8Array(await suite.kem.serializePublicKey(recipientKeyPair.publicKey));
  const recipientPrivateKey = new Uint8Array(await suite.kem.serializePrivateKey(recipientKeyPair.privateKey));
  return {
    factorMode,
    factorModeName: modeName,
    factorHex: hex(factor),
    requestLocatorBase64url: base64url(requestLocator),
    writePrkHex: hex(writePrk),
    schemaKeyHex: hex(expand(writePrk, "kryptex/v1/request/schema-key", 32)),
    writeTokenBase64url: base64url(expand(writePrk, "kryptex/v1/request/write-token", 32)),
    ownerPrkHex: hex(ownerPrk),
    ownerTokenBase64url: base64url(expand(ownerPrk, "kryptex/v1/request/owner-token", 32)),
    hpkeIkmHex: hex(hpkeIkm),
    recipientPrivateKeyHex: hex(recipientPrivateKey),
    recipientPublicKeyBase64url: base64url(recipientPublicKey),
  };
}

function capabilityTag(serverKey, resourceKind, capabilityKind, locator, token) {
  return hmac(
    serverKey,
    concat(
      utf8("kryptex/v1/server-capability-tag"),
      Uint8Array.of(0, resourceKind, capabilityKind),
      locator,
      token,
    ),
  );
}

function rateLimitTag(rateLimitKey, resourceKind, locator) {
  return hmac(
    rateLimitKey,
    concat(
      utf8("kryptex/v1/rate-limit-locator"),
      Uint8Array.of(0, resourceKind),
      locator,
    ),
  );
}

export async function deriveVectors() {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  const sendSeed = sequence(0x00, 32);
  const manageSeed = sequence(0x20, 32);
  const randomSecret = sequence(0x40, 16);
  const randomFactor = expand(
    extract("kryptex/v1/factor/random", randomSecret),
    "kryptex/v1/factor/random",
    32,
  );
  const passphraseSalt = sequence(0x60, 16);
  const requestLocator = sequence(0x70, 16);
  const writeSeed = sequence(0x80, 32);
  const ownerSeed = sequence(0xa0, 32);
  const serverKey = sequence(0xc0, 32);
  const rateLimitKey = sequence(0xe0, 32);
  const permitIssuanceKey = sequence(0x31, 32);
  const requestId = fromHex("550e8400e29b41d4a716446655440000");
  const passphrase = "correct horse battery staple";
  const wrongPassphrase = "correct horse battery stapler";

  const passphraseFactor = await argon2id({
    password: utf8(passphrase),
    salt: passphraseSalt,
    iterations: 3,
    parallelism: 1,
    memorySize: 65536,
    hashLength: 32,
    outputType: "binary",
  });
  const wrongPassphraseFactor = await argon2id({
    password: utf8(wrongPassphrase),
    salt: passphraseSalt,
    iterations: 3,
    parallelism: 1,
    memorySize: 65536,
    hashLength: 32,
    outputType: "binary",
  });
  const factors = [zero32, passphraseFactor, randomFactor];

  const sendSchedules = factors.map((factor, factorMode) =>
    sendSchedule(sendSeed, manageSeed, factorMode, factor),
  );
  const requestSchedules = [];
  for (const [factorMode, factor] of factors.entries()) {
    requestSchedules.push(
      await requestSchedule(requestLocator, writeSeed, ownerSeed, factorMode, factor, suite),
    );
  }

  const locator = Buffer.from(sendSchedules[0].locatorBase64url, "base64url");
  const manageToken = Buffer.from(sendSchedules[0].manageTokenBase64url, "base64url");
  const recipientPublicKey = Buffer.from(requestSchedules[0].recipientPublicKeyBase64url, "base64url");
  const saltForMode = (factorMode) => (factorMode === 1 ? passphraseSalt : new Uint8Array(16));

  const bundles = [];
  for (const factorMode of [0, 1, 2]) {
    const recipient = kxb(
      1,
      concat(sendSeed, Uint8Array.of(factorMode), saltForMode(factorMode), u64(serverExpiresAt)),
    );
    bundles.push({
      id: `send-recipient-${sendSchedules[factorMode].factorModeName}`,
      kind: 1,
      bodyLength: 57,
      factorMode,
      bytesHex: hex(recipient),
      base64url: base64url(recipient),
    });
  }
  const management = kxb(2, concat(locator, manageSeed, u64(serverExpiresAt)));
  bundles.push({
    id: "send-management",
    kind: 2,
    bodyLength: 56,
    bytesHex: hex(management),
    base64url: base64url(management),
  });
  for (const factorMode of [0, 1, 2]) {
    const write = kxb(
      3,
      concat(
        requestLocator,
        writeSeed,
        Uint8Array.of(factorMode),
        saltForMode(factorMode),
        recipientPublicKey,
        u64(serverExpiresAt),
      ),
    );
    bundles.push({
      id: `request-write-${requestSchedules[factorMode].factorModeName}`,
      kind: 3,
      bodyLength: 105,
      factorMode,
      bytesHex: hex(write),
      base64url: base64url(write),
    });
  }
  const pickup = kxb(4, concat(requestLocator, ownerSeed, u64(serverExpiresAt)));
  bundles.push({
    id: "request-pickup",
    kind: 4,
    bodyLength: 56,
    bytesHex: hex(pickup),
    base64url: base64url(pickup),
  });

  const sendText = { kind: "text", text: "db_password=Tr0ub4dor&3" };
  const sendFields = {
    fields: [
      { label: "Username", type: "text", value: "deploy-bot" },
      { label: "API key", type: "secret", value: "kx_test_7f4b0f" },
      { label: "Deploy key", type: "long-secret", value: "-----BEGIN KEY-----\nZGVwbG95\n-----END KEY-----" },
    ],
    kind: "fields",
  };
  const schema = {
    fields: [
      {
        help: "Paste the token without surrounding spaces.",
        id: "apitoken",
        label: "API token",
        required: true,
        type: "secret",
      },
      {
        help: "",
        id: "context1",
        label: "Optional context",
        required: false,
        type: "long-text",
      },
      {
        help: "Do not include an account password.",
        id: "warning1",
        label: "Security note",
        required: false,
        type: "instruction",
      },
    ],
    kind: "request-schema",
    recipientPublicKey: base64url(recipientPublicKey),
    title: "Deployment credential",
  };
  const response = {
    answers: [
      { id: "apitoken", value: "kx_live_a9c5e1" },
      { id: "context1", value: "Rotate after the deployment." },
    ],
    kind: "request-response",
    schema,
  };

  const payloads = [
    { id: "send-text", value: sendText },
    { id: "send-fields", value: sendFields },
    { id: "request-schema", value: schema },
    { id: "request-response", value: response },
  ].map(({ id, value }) => {
    const bytes = jcs(value);
    return {
      id,
      object: value,
      jcs: new TextDecoder().decode(bytes),
      utf8Hex: hex(bytes),
      sha256Hex: hex(sha256(bytes)),
    };
  });
  const canonicalizationCases = [
    {
      id: "unicode-and-utf16-key-order",
      value: {
        "\u20ac": "Euro",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew letter",
        "1": "One",
        "😀": "Emoji",
        "\u0080": "Control range boundary",
        "ö": "Latin small letter",
      },
    },
    {
      id: "escaping-and-combining-text",
      value: {
        controls: "\b\t\n\f\r",
        path: "C:\\vault\\\"quoted\"/entry",
        text: "Český klíč 🔐 é",
      },
    },
  ].map(({ id, value }) => {
    const bytes = jcs(value);
    return {
      id,
      object: value,
      jcs: new TextDecoder().decode(bytes),
      utf8Hex: hex(bytes),
      sha256Hex: hex(sha256(bytes)),
    };
  });
  const invalidJcsAndPayloads = [
    { id: "duplicate-raw-json-key", rawJson: "{\"kind\":\"text\",\"kind\":\"text\",\"text\":\"x\"}", error: "duplicate_json_key" },
    { id: "lone-high-surrogate", rawJson: "{\"kind\":\"text\",\"text\":\"\\ud800\"}", error: "invalid_unicode" },
    { id: "lone-low-surrogate", rawJson: "{\"kind\":\"text\",\"text\":\"\\udc00\"}", error: "invalid_unicode" },
    { id: "noncanonical-key-order", rawJson: "{\"text\":\"x\",\"kind\":\"text\"}", error: "non_canonical_json" },
    { id: "forbidden-number", object: { kind: "text", text: 1 }, error: "forbidden_json_type" },
    { id: "forbidden-null", object: { kind: "text", text: null }, error: "forbidden_json_type" },
    { id: "send-text-empty", object: { kind: "text", text: "" }, error: "invalid_text" },
    { id: "send-extra-key", object: { extra: "x", kind: "text", text: "x" }, error: "unexpected_key" },
    { id: "send-field-missing-type", object: { fields: [{ label: "Name", value: "x" }], kind: "fields" }, error: "missing_key" },
    { id: "send-field-unknown-type", object: { fields: [{ label: "Name", type: "instruction", value: "x" }], kind: "fields" }, error: "invalid_field_type" },
    { id: "schema-duplicate-id", object: { ...schema, fields: [schema.fields[0], { ...schema.fields[1], id: schema.fields[0].id }] }, error: "duplicate_field_id" },
    { id: "schema-invalid-id", object: { ...schema, fields: [{ ...schema.fields[0], id: "UPPER" }, ...schema.fields.slice(1)] }, error: "invalid_field_id" },
    { id: "instruction-required", object: { ...schema, fields: [...schema.fields.slice(0, 2), { ...schema.fields[2], required: true }] }, error: "invalid_instruction" },
    { id: "response-answer-order", object: { ...response, answers: [...response.answers].reverse() }, error: "answer_order_mismatch" },
    { id: "response-missing-answer", object: { ...response, answers: response.answers.slice(0, 1) }, error: "answer_count_mismatch" },
    { id: "response-instruction-answer", object: { ...response, answers: [...response.answers, { id: "warning1", value: "ignored" }] }, error: "answer_count_mismatch" },
    { id: "response-required-empty", object: { ...response, answers: [{ id: "apitoken", value: "" }, response.answers[1]] }, error: "required_answer_empty" },
    { id: "response-schema-mismatch", object: { ...response, schema: { ...schema, title: "Changed" } }, expectedSchema: schema, error: "schema_mismatch" },
    { id: "malformed-utf8", utf8Hex: "7b226b696e64223a2274657874222c2274657874223a22c328227d", error: "malformed_utf8" },
  ];
  const payloadById = new Map(payloads.map((entry) => [entry.id, fromHex(entry.utf8Hex)]));
  const schemaPayload = payloadById.get("request-schema");
  const schemaDigest = sha256(schemaPayload);

  const kxeEnvelopes = [];
  for (const factorMode of [0, 1, 2]) {
    const sendPayload = factorMode === 0
      ? payloadById.get("send-text")
      : payloadById.get("send-fields");
    const sendNonce = sequence(0x10 + factorMode * 0x10, 12);
    const sendHeader = kxeHeader(1, factorMode, factorMode + 1, zero32, sendNonce);
    const sendPlaintext = paddedPlaintext(sendPayload, 0x40 + factorMode * 0x10);
    const sendCiphertext = aesGcmEncrypt(
      fromHex(sendSchedules[factorMode].contentKeyHex),
      sendNonce,
      sendHeader,
      sendPlaintext,
    );
    const sendEnvelope = concat(sendHeader, sendCiphertext);
    kxeEnvelopes.push({
      id: `send-${sendSchedules[factorMode].factorModeName}`,
      contentMode: 1,
      factorMode,
      clientNotAfter,
      maxRetrievals: factorMode + 1,
      schemaDigestHex: hex(zero32),
      nonceHex: hex(sendNonce),
      payloadId: factorMode === 0 ? "send-text" : "send-fields",
      padding: { construction: "byte[i] = (offset + i) mod 256", offset: 0x40 + factorMode * 0x10 },
      plaintextLength: sendPlaintext.length,
      plaintextSha256Hex: hex(sha256(sendPlaintext)),
      envelopeLength: sendEnvelope.length,
      envelopeSha256Hex: hex(sha256(sendEnvelope)),
      envelopeBase64url: base64url(sendEnvelope),
    });

    const schemaNonce = sequence(0x70 + factorMode * 0x10, 12);
    const schemaHeader = kxeHeader(2, factorMode, 0, schemaDigest, schemaNonce);
    const schemaPlaintext = paddedPlaintext(schemaPayload, 0xa0 + factorMode * 0x10);
    const schemaCiphertext = aesGcmEncrypt(
      fromHex(requestSchedules[factorMode].schemaKeyHex),
      schemaNonce,
      schemaHeader,
      schemaPlaintext,
    );
    const schemaEnvelope = concat(schemaHeader, schemaCiphertext);
    kxeEnvelopes.push({
      id: `request-schema-${requestSchedules[factorMode].factorModeName}`,
      contentMode: 2,
      factorMode,
      clientNotAfter,
      maxRetrievals: 0,
      schemaDigestHex: hex(schemaDigest),
      nonceHex: hex(schemaNonce),
      payloadId: "request-schema",
      padding: { construction: "byte[i] = (offset + i) mod 256", offset: 0xa0 + factorMode * 0x10 },
      plaintextLength: schemaPlaintext.length,
      plaintextSha256Hex: hex(sha256(schemaPlaintext)),
      envelopeLength: schemaEnvelope.length,
      envelopeSha256Hex: hex(sha256(schemaEnvelope)),
      envelopeBase64url: base64url(schemaEnvelope),
    });
  }

  const responsePayload = payloadById.get("request-response");
  const responsePlaintext = paddedPlaintext(responsePayload, 0xd0);
  const hpkeEkm = sequence(0x11, 32);
  const recipientKeyPair = await suite.kem.deriveKeyPair(fromHex(requestSchedules[0].hpkeIkmHex));
  const info = concat(utf8("kryptex/v1/request/response"), requestLocator, schemaDigest);
  const sender = await suite.createSenderContext({
    recipientPublicKey: recipientKeyPair.publicKey,
    info,
    ekm: hpkeEkm,
  });
  const enc = new Uint8Array(sender.enc);
  const kxrHeader = concat(
    utf8("KXR1"),
    Uint8Array.of(1, 0),
    u16(0),
    u64(clientNotAfter),
    schemaDigest,
    u16(enc.length),
    u32(responsePlaintext.length + 16),
    enc,
  );
  const hpkeCiphertext = new Uint8Array(await sender.seal(responsePlaintext, kxrHeader));
  const kxrEnvelope = concat(kxrHeader, hpkeCiphertext);
  const receipt = sha256(kxrEnvelope);

  const permitSeed = hmac(
    permitIssuanceKey,
    concat(utf8("kryptex/v1/create-permit/issuance"), Uint8Array.of(0), requestId),
  );
  const permitPrk = extract("kryptex/v1/create-permit/locator", permitSeed);
  const permitLocator = expand(permitPrk, "kryptex/v1/create-permit/locator", 16);
  const permitToken = expand(permitPrk, "kryptex/v1/create-permit/token", 32);

  const serverTags = [
    {
      id: "send-retrieve-random-factor",
      resourceKind: 1,
      capabilityKind: 1,
      locator,
      token: Buffer.from(sendSchedules[2].retrieveTokenBase64url, "base64url"),
    },
    {
      id: "send-manage",
      resourceKind: 1,
      capabilityKind: 2,
      locator,
      token: manageToken,
    },
    {
      id: "request-write-passphrase",
      resourceKind: 2,
      capabilityKind: 1,
      locator: requestLocator,
      token: Buffer.from(requestSchedules[1].writeTokenBase64url, "base64url"),
    },
    {
      id: "request-owner",
      resourceKind: 2,
      capabilityKind: 2,
      locator: requestLocator,
      token: Buffer.from(requestSchedules[0].ownerTokenBase64url, "base64url"),
    },
    {
      id: "create-permit",
      resourceKind: 3,
      capabilityKind: 3,
      locator: permitLocator,
      token: permitToken,
    },
  ].map((entry) => ({
    id: entry.id,
    resourceKind: entry.resourceKind,
    capabilityKind: entry.capabilityKind,
    locatorBase64url: base64url(entry.locator),
    tokenBase64url: base64url(entry.token),
    tagHex: hex(capabilityTag(serverKey, entry.resourceKind, entry.capabilityKind, entry.locator, entry.token)),
  }));

  const rateLimitTags = [
    { id: "send", resourceKind: 1, locator },
    { id: "request", resourceKind: 2, locator: requestLocator },
    { id: "create-permit", resourceKind: 3, locator: permitLocator },
  ].map((entry) => ({
    id: entry.id,
    resourceKind: entry.resourceKind,
    locatorBase64url: base64url(entry.locator),
    tagBase64url: base64url(rateLimitTag(rateLimitKey, entry.resourceKind, entry.locator)),
  }));

  const wrongRandomFactor = randomFactor.slice();
  wrongRandomFactor[31] ^= 1;
  const wrongPassphraseSend = sendSchedule(sendSeed, manageSeed, 1, wrongPassphraseFactor);
  const wrongRandomSend = sendSchedule(sendSeed, manageSeed, 2, wrongRandomFactor);
  const wrongPassphraseRequest = await requestSchedule(
    requestLocator,
    writeSeed,
    ownerSeed,
    1,
    wrongPassphraseFactor,
    suite,
  );
  const wrongRandomRequest = await requestSchedule(
    requestLocator,
    writeSeed,
    ownerSeed,
    2,
    wrongRandomFactor,
    suite,
  );

  const boundaryDefinitions = [
    { id: "empty-payload", payloadLength: 0, expectedBucketLength: 4096 },
    { id: "bucket-4096-max", payloadLength: 4092, expectedBucketLength: 4096 },
    { id: "bucket-4096-transition", payloadLength: 4093, expectedBucketLength: 16384 },
    { id: "bucket-16384-max", payloadLength: 16380, expectedBucketLength: 16384 },
    { id: "bucket-16384-transition", payloadLength: 16381, expectedBucketLength: 65536 },
    { id: "bucket-65536-max", payloadLength: 65532, expectedBucketLength: 65536 },
    { id: "bucket-65536-transition", payloadLength: 65533, expectedBucketLength: 262144 },
    { id: "bucket-262144-max", payloadLength: 262140, expectedBucketLength: 262144 },
    { id: "bucket-262144-transition", payloadLength: 262141, expectedBucketLength: 1048576 },
    { id: "bucket-1048576-max", payloadLength: 1048572, expectedBucketLength: 1048576 },
  ];
  const boundaryCases = boundaryDefinitions.map((definition, caseIndex) => {
    const payload = pattern(0x21 + caseIndex, definition.payloadLength);
    const plaintext = paddedPlaintextForBucket(payload, 0x91 + caseIndex, definition.expectedBucketLength);
    return {
      ...definition,
      payload: { construction: "byte[i] = (offset + i) mod 256", offset: 0x21 + caseIndex },
      padding: { construction: "byte[i] = (offset + i) mod 256", offset: 0x91 + caseIndex },
      plaintextLength: plaintext.length,
      plaintextSha256Hex: hex(sha256(plaintext)),
      kxeEnvelopeLength: 62 + plaintext.length + 16,
      kxrEnvelopeLength: 86 + plaintext.length + 16,
    };
  });
  boundaryCases.push({
    id: "maximum-overflow",
    payloadLength: 1048573,
    error: "payload_too_large",
  });

  const recipientNone = fromHex(bundles.find((entry) => entry.id === "send-recipient-none").bytesHex);
  const writeNone = fromHex(bundles.find((entry) => entry.id === "request-write-none").bytesHex);
  const kxeSendNone = Buffer.from(kxeEnvelopes.find((entry) => entry.id === "send-none").envelopeBase64url, "base64url");
  const kxeSchemaNone = Buffer.from(kxeEnvelopes.find((entry) => entry.id === "request-schema-none").envelopeBase64url, "base64url");
  const kxrBadReserved = mutate(kxrEnvelope, 6, 1);
  const writeWrongPublicKey = mutate(writeNone, 73, writeNone[73] ^ 1);
  const kxrWrongSchemaDigest = mutate(kxrEnvelope, 16, kxrEnvelope[16] ^ 1);
  const kxrWrongExpiry = kxrEnvelope.slice();
  kxrWrongExpiry.set(u64(clientNotAfter + 1), 8);
  const unsafeTimestamp = Number.MAX_SAFE_INTEGER + 1;
  const managementUnsafeTimestamp = management.slice();
  managementUnsafeTimestamp.set(u64(unsafeTimestamp), 56);
  const sendPlaintextForNegative = paddedPlaintext(payloadById.get("send-text"), 0x40);
  const schemaPlaintextForNegative = paddedPlaintext(schemaPayload, 0xa0);
  const sendDigestHeader = kxeHeader(1, 0, 1, Uint8Array.from({ length: 32 }, () => 1), sequence(0x10, 12));
  const sendDigestEnvelope = concat(
    sendDigestHeader,
    aesGcmEncrypt(fromHex(sendSchedules[0].contentKeyHex), sequence(0x10, 12), sendDigestHeader, sendPlaintextForNegative),
  );
  const schemaRetrievalHeader = kxeHeader(2, 0, 1, schemaDigest, sequence(0x70, 12));
  const schemaRetrievalEnvelope = concat(
    schemaRetrievalHeader,
    aesGcmEncrypt(fromHex(requestSchedules[0].schemaKeyHex), sequence(0x70, 12), schemaRetrievalHeader, schemaPlaintextForNegative),
  );
  const wrongSchemaDigest = schemaDigest.slice();
  wrongSchemaDigest[0] ^= 1;
  const schemaDigestHeader = kxeHeader(2, 0, 0, wrongSchemaDigest, sequence(0x70, 12));
  const schemaDigestEnvelope = concat(
    schemaDigestHeader,
    aesGcmEncrypt(fromHex(requestSchedules[0].schemaKeyHex), sequence(0x70, 12), schemaDigestHeader, schemaPlaintextForNegative),
  );
  const nonMinimalPlaintext = paddedPlaintextForBucket(payloadById.get("send-text"), 0x40, 16384);
  const nonMinimalHeader = kxeHeader(1, 0, 1, zero32, sequence(0x10, 12));
  const nonMinimalEnvelope = concat(
    nonMinimalHeader,
    aesGcmEncrypt(fromHex(sendSchedules[0].contentKeyHex), sequence(0x10, 12), nonMinimalHeader, nonMinimalPlaintext),
  );
  const overflowingPlaintext = pattern(0x55, 4096);
  overflowingPlaintext.set(u32(4093), 0);
  const overflowingHeader = kxeHeader(1, 0, 1, zero32, sequence(0x10, 12));
  const overflowingEnvelope = concat(
    overflowingHeader,
    aesGcmEncrypt(fromHex(sendSchedules[0].contentKeyHex), sequence(0x10, 12), overflowingHeader, overflowingPlaintext),
  );
  const kxeUnsafeTimestamp = Uint8Array.from(kxeSendNone);
  kxeUnsafeTimestamp.set(u64(unsafeTimestamp), 8);
  const kxrUnsafeTimestamp = kxrEnvelope.slice();
  kxrUnsafeTimestamp.set(u64(unsafeTimestamp), 8);

  const negative = {
    malformedExternalEncodings: [
      { id: "base64url-padding", kind: "base64url", value: `${base64url(requestLocator)}=`, error: "non_canonical_base64url" },
      { id: "base64url-whitespace", kind: "base64url", value: `${base64url(requestLocator)}\n`, error: "non_canonical_base64url" },
      { id: "base64url-standard-alphabet-plus", kind: "base64url", value: "+w", error: "non_canonical_base64url" },
      { id: "base64url-standard-alphabet-slash", kind: "base64url", value: "/w", error: "non_canonical_base64url" },
      { id: "base64url-nonzero-pad-bits", kind: "base64url", value: "_x", error: "non_canonical_base64url" },
      { id: "crockford-letter-u", kind: "crockford-base32", value: crockfordEncode(randomSecret).replace("0", "U"), error: "invalid_random_factor" },
      { id: "crockford-whitespace", kind: "crockford-base32", value: `${crockfordEncode(randomSecret)} `, error: "invalid_random_factor" },
      { id: "crockford-bad-hyphen", kind: "crockford-base32", value: crockfordEncode(randomSecret).replace("-", "--"), error: "invalid_random_factor" },
      { id: "crockford-nonzero-pad-bits", kind: "crockford-base32", value: `${crockfordEncode(randomSecret).slice(0, -1)}1`, error: "invalid_random_factor" },
      { id: "crockford-short", kind: "crockford-base32", value: crockfordEncode(randomSecret).slice(0, -1), error: "invalid_random_factor" },
    ],
    malformedContainers: [
      { id: "kxb-bad-magic", container: "KXB1", valueBase64url: base64url(mutate(recipientNone, 0, 0)), error: "invalid_magic" },
      { id: "kxb-unsupported-kind", container: "KXB1", valueBase64url: base64url(mutate(recipientNone, 4, 5)), error: "unsupported_kind" },
      { id: "kxb-bad-version", container: "KXB1", valueBase64url: base64url(mutate(recipientNone, 5, 2)), error: "unsupported_version" },
      { id: "kxb-bad-body-length", container: "KXB1", valueBase64url: base64url(mutate(recipientNone, 7, 58)), error: "invalid_length" },
      { id: "kxb-trailing-byte", container: "KXB1", valueBase64url: base64url(concat(recipientNone, Uint8Array.of(0))), error: "trailing_bytes" },
      { id: "kxb-unsupported-factor", container: "KXB1", valueBase64url: base64url(mutate(recipientNone, 40, 3)), error: "unsupported_factor_mode" },
      { id: "kxb-nonzero-none-salt", container: "KXB1", valueBase64url: base64url(mutate(recipientNone, 41, 1)), error: "invalid_salt" },
      { id: "kxb-unsafe-timestamp", container: "KXB1", valueBase64url: base64url(managementUnsafeTimestamp), error: "unsafe_timestamp" },
      { id: "kxe-bad-magic", container: "KXE1", valueBase64url: base64url(mutate(kxeSendNone, 0, 0)), error: "invalid_magic" },
      { id: "kxe-bad-suite", container: "KXE1", valueBase64url: base64url(mutate(kxeSendNone, 4, 2)), error: "unsupported_suite" },
      { id: "kxe-unsupported-content-mode", container: "KXE1", valueBase64url: base64url(mutate(kxeSendNone, 5, 3)), error: "unsupported_content_mode" },
      { id: "kxe-unsupported-factor", container: "KXE1", valueBase64url: base64url(mutate(kxeSendNone, 6, 3)), error: "unsupported_factor_mode" },
      { id: "kxe-nonzero-flags", container: "KXE1", valueBase64url: base64url(mutate(kxeSendNone, 7, 1)), error: "reserved_bits" },
      { id: "kxe-unsafe-timestamp", container: "KXE1", valueBase64url: base64url(kxeUnsafeTimestamp), error: "unsafe_timestamp" },
      { id: "kxe-send-zero-retrievals", container: "KXE1", valueBase64url: base64url(mutate(kxeSendNone, 17, 0)), error: "invalid_retrieval_count" },
      { id: "kxe-send-too-many-retrievals", container: "KXE1", valueBase64url: base64url(mutate(kxeSendNone, 17, 11)), error: "invalid_retrieval_count" },
      { id: "kxe-send-nonzero-schema-digest", container: "KXE1", valueBase64url: base64url(sendDigestEnvelope), error: "invalid_schema_digest" },
      { id: "kxe-schema-nonzero-retrievals", container: "KXE1", valueBase64url: base64url(schemaRetrievalEnvelope), error: "invalid_retrieval_count" },
      { id: "kxe-schema-digest-mismatch", container: "KXE1", valueBase64url: base64url(schemaDigestEnvelope), error: "schema_digest_mismatch", keySource: "request-schema-none" },
      { id: "kxe-truncated", container: "KXE1", valueBase64url: base64url(kxeSendNone.slice(0, -1)), error: "invalid_length" },
      { id: "kxe-nonminimal-bucket", container: "KXE1", valueBase64url: base64url(nonMinimalEnvelope), error: "nonminimal_bucket", keySource: "send-none" },
      { id: "kxe-payload-length-overflow", container: "KXE1", valueBase64url: base64url(overflowingEnvelope), error: "invalid_payload_length", keySource: "send-none" },
      { id: "kxr-bad-magic", container: "KXR1", valueBase64url: base64url(mutate(kxrEnvelope, 0, 0)), error: "invalid_magic" },
      { id: "kxr-bad-suite", container: "KXR1", valueBase64url: base64url(mutate(kxrEnvelope, 4, 2)), error: "unsupported_suite" },
      { id: "kxr-nonzero-flags", container: "KXR1", valueBase64url: base64url(mutate(kxrEnvelope, 5, 1)), error: "reserved_bits" },
      { id: "kxr-nonzero-reserved", container: "KXR1", valueBase64url: base64url(kxrBadReserved), error: "reserved_bits" },
      { id: "kxr-unsafe-timestamp", container: "KXR1", valueBase64url: base64url(kxrUnsafeTimestamp), error: "unsafe_timestamp" },
      { id: "kxr-bad-enc-length", container: "KXR1", valueBase64url: base64url(mutate(kxrEnvelope, 49, 31)), error: "invalid_enc_length" },
      { id: "kxr-bad-ciphertext-length", container: "KXR1", valueBase64url: base64url(mutate(kxrEnvelope, 53, 17)), error: "invalid_length" },
      { id: "kxr-invalid-bucket", container: "KXR1", valueBase64url: base64url(kxrEnvelope.slice(0, -1)), error: "invalid_length" },
      { id: "kxr-trailing-byte", container: "KXR1", valueBase64url: base64url(concat(kxrEnvelope, Uint8Array.of(0))), error: "trailing_bytes" },
    ],
    wrongFactors: [
      {
        id: "send-passphrase",
        correctTokenBase64url: sendSchedules[1].retrieveTokenBase64url,
        wrongFactorHex: hex(wrongPassphraseFactor),
        wrongContentKeyHex: wrongPassphraseSend.contentKeyHex,
        wrongTokenBase64url: wrongPassphraseSend.retrieveTokenBase64url,
        expectedAuthorization: "unavailable",
        expectedDecryption: "authentication_failed",
      },
      {
        id: "send-random-factor",
        correctTokenBase64url: sendSchedules[2].retrieveTokenBase64url,
        wrongFactorHex: hex(wrongRandomFactor),
        wrongContentKeyHex: wrongRandomSend.contentKeyHex,
        wrongTokenBase64url: wrongRandomSend.retrieveTokenBase64url,
        expectedAuthorization: "unavailable",
        expectedDecryption: "authentication_failed",
      },
      {
        id: "request-passphrase",
        correctTokenBase64url: requestSchedules[1].writeTokenBase64url,
        wrongFactorHex: hex(wrongPassphraseFactor),
        wrongSchemaKeyHex: wrongPassphraseRequest.schemaKeyHex,
        wrongTokenBase64url: wrongPassphraseRequest.writeTokenBase64url,
        expectedAuthorization: "unavailable",
        expectedDecryption: "authentication_failed",
      },
      {
        id: "request-random-factor",
        correctTokenBase64url: requestSchedules[2].writeTokenBase64url,
        wrongFactorHex: hex(wrongRandomFactor),
        wrongSchemaKeyHex: wrongRandomRequest.schemaKeyHex,
        wrongTokenBase64url: wrongRandomRequest.writeTokenBase64url,
        expectedAuthorization: "unavailable",
        expectedDecryption: "authentication_failed",
      },
    ],
    crossContainerMismatches: [
      { id: "recipient-factor-vs-send-envelope", left: "send-recipient-none", right: "send-random-factor", error: "factor_mode_mismatch" },
      { id: "write-factor-vs-schema-envelope", left: "request-write-none", right: "request-schema-passphrase", error: "factor_mode_mismatch" },
      { id: "write-public-key-vs-schema", left: "request-write-none", valueBase64url: base64url(writeWrongPublicKey), mutation: "flip public-key byte 0", error: "recipient_public_key_mismatch" },
      { id: "response-schema-digest-vs-schema", left: "response", valueBase64url: base64url(kxrWrongSchemaDigest), mutation: "flip schemaDigest byte 0", error: "schema_digest_mismatch" },
      { id: "response-expiry-vs-schema", left: "response", valueBase64url: base64url(kxrWrongExpiry), mutation: "increment clientNotAfter", error: "client_not_after_mismatch" },
      { id: "response-at-kxe-endpoint", valueBase64url: base64url(kxrEnvelope), error: "invalid_magic" },
      { id: "send-at-kxr-endpoint", valueBase64url: base64url(kxeSendNone), error: "invalid_magic" },
    ],
  };

  return {
    "manifest.json": {
      fixtureSchema: "kryptex-protocol-vectors/v1",
      protocolVersion: 1,
      warning: "Sequential entropy and patterned padding are deterministic test inputs only.",
      fixedInputs: {
        sendSeedHex: hex(sendSeed),
        manageSeedHex: hex(manageSeed),
        randomSecretHex: hex(randomSecret),
        randomFactorHex: hex(randomFactor),
        passphrase,
        wrongPassphrase,
        passphraseSaltHex: hex(passphraseSalt),
        requestLocatorHex: hex(requestLocator),
        writeSeedHex: hex(writeSeed),
        ownerSeedHex: hex(ownerSeed),
        serverHmacKeyHex: hex(serverKey),
        rateLimitHmacKeyHex: hex(rateLimitKey),
        permitIssuanceKeyHex: hex(permitIssuanceKey),
        permitRequestIdHex: hex(requestId),
        hpkeEphemeralIkmHex: hex(hpkeEkm),
        clientNotAfter,
        serverExpiresAt,
      },
      files: ["encoding.json", "jcs.json", "key-schedules.json", "bundles.json", "boundaries.json", "envelopes.json", "server-tags.json", "negative.json"],
    },
    "encoding.json": {
      base64url: [
        { id: "empty", bytesHex: "", canonical: "" },
        { id: "one-byte", bytesHex: "ff", canonical: "_w" },
        { id: "locator", bytesHex: hex(requestLocator), canonical: base64url(requestLocator) },
        { id: "factor", bytesHex: hex(randomFactor), canonical: base64url(randomFactor) },
      ],
      crockfordBase32: {
        bytesHex: hex(randomSecret),
        canonicalDisplay: crockfordEncode(randomSecret),
        acceptedAliasDisplay: crockfordEncode(randomSecret).toLowerCase().replaceAll("0", "o").replaceAll("1", "l"),
        acceptedHyphenVariants: [
          crockfordEncode(randomSecret).replaceAll("-", ""),
          crockfordEncode(randomSecret).replaceAll("-", "").replace(/(.{5})/, "$1-"),
          crockfordEncode(randomSecret).replaceAll("-", "").replace(/(.{10})/, "$1-"),
          crockfordEncode(randomSecret).replaceAll("-", "").replace(/(.{20})/, "$1-"),
        ],
        decodedLength: 16,
        bitOrder: "most-significant-bit first; final two pad bits are zero",
        expansion: {
          extractLabel: "kryptex/v1/factor/random",
          expandLabel: "kryptex/v1/factor/random",
          factorHex: hex(randomFactor),
        },
      },
    },
    "jcs.json": { payloads, canonicalizationCases, invalidJcsAndPayloads },
    "key-schedules.json": {
      argon2id: {
        passwordUtf8Hex: hex(utf8(passphrase)),
        saltHex: hex(passphraseSalt),
        version: 19,
        memoryKiB: 65536,
        iterations: 3,
        parallelism: 1,
        outputLength: 32,
        outputHex: hex(passphraseFactor),
      },
      sendSeedHex: hex(sendSeed),
      manageSeedHex: hex(manageSeed),
      send: sendSchedules,
      requestLocatorHex: hex(requestLocator),
      writeSeedHex: hex(writeSeed),
      ownerSeedHex: hex(ownerSeed),
      request: requestSchedules,
    },
    "bundles.json": { bundles },
    "boundaries.json": {
      allowedBucketLengths: [4096, 16384, 65536, 262144, 1048576],
      cases: boundaryCases,
    },
    "envelopes.json": {
      fixtureBucketLength: bucketLength,
      kxe1: kxeEnvelopes,
      kxr1: {
        id: "request-response",
        clientNotAfter,
        schemaDigestHex: hex(schemaDigest),
        infoHex: hex(info),
        aadHex: hex(kxrHeader),
        encHex: hex(enc),
        hpkeEphemeralIkmHex: hex(hpkeEkm),
        payloadId: "request-response",
        padding: { construction: "byte[i] = (offset + i) mod 256", offset: 0xd0 },
        plaintextLength: responsePlaintext.length,
        plaintextSha256Hex: hex(sha256(responsePlaintext)),
        ciphertextLength: hpkeCiphertext.length,
        envelopeLength: kxrEnvelope.length,
        envelopeSha256Hex: hex(receipt),
        envelopeBase64url: base64url(kxrEnvelope),
        receiptBase64url: base64url(receipt),
        receiptDisplay: hex(receipt).toUpperCase().match(/.{8}/g).join(" "),
      },
    },
    "server-tags.json": {
      serverKeyHex: hex(serverKey),
      rateLimitKeyHex: hex(rateLimitKey),
      capabilityTags: serverTags,
      rateLimitTags,
      createPermit: {
        requestIdHex: hex(requestId),
        issuanceKeyHex: hex(permitIssuanceKey),
        permitSeedHex: hex(permitSeed),
        permitPrkHex: hex(permitPrk),
        permitLocatorBase64url: base64url(permitLocator),
        permitTokenBase64url: base64url(permitToken),
      },
    },
    "negative.json": negative,
  };
}

export const rfc9180BaseX25519Aes256 = {
  infoHex: "4f6465206f6e2061204772656369616e2055726e",
  ikmRHex: "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee",
  ikmEHex: "2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9",
  recipientPublicKeyHex: "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
  ephemeralPublicKeyHex: "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
  aadHex: "436f756e742d30",
  plaintextHex: "4265617574792069732074727574682c20747275746820626561757479",
  ciphertextHex: "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
};
