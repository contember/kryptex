import { deepStrictEqual, equal, notEqual, rejects } from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { argon2id } from "@noble/hashes/argon2.js";

const directory = dirname(fileURLToPath(import.meta.url));
const vectorDirectory = resolve(directory, "../../vectors/v1");
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const bucketLengths = [4096, 16384, 65536, 262144, 1048576];
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

const bundleScenarios = new Map([
  ["send-recipient-none", { kind: 1, bodyLength: 57, factorMode: 0, serverExpiresAt: 1800003000 }],
  ["send-recipient-passphrase", { kind: 1, bodyLength: 57, factorMode: 1, serverExpiresAt: 1800003000 }],
  ["send-recipient-random-factor", { kind: 1, bodyLength: 57, factorMode: 2, serverExpiresAt: 1800003000 }],
  ["send-management", { kind: 2, bodyLength: 56, serverExpiresAt: 1800003000 }],
  ["request-write-none", { kind: 3, bodyLength: 105, factorMode: 0, serverExpiresAt: 1800003000 }],
  ["request-write-passphrase", { kind: 3, bodyLength: 105, factorMode: 1, serverExpiresAt: 1800003000 }],
  ["request-write-random-factor", { kind: 3, bodyLength: 105, factorMode: 2, serverExpiresAt: 1800003000 }],
  ["request-pickup", { kind: 4, bodyLength: 56, serverExpiresAt: 1800003000 }],
]);

const kxeScenarios = new Map([
  ["send-none", { contentMode: 1, factorMode: 0, clientNotAfter: 1800003600, maxRetrievals: 1, payloadId: "send-text", digest: "zero" }],
  ["request-schema-none", { contentMode: 2, factorMode: 0, clientNotAfter: 1800003600, maxRetrievals: 0, payloadId: "request-schema", digest: "payload" }],
  ["send-passphrase", { contentMode: 1, factorMode: 1, clientNotAfter: 1800003600, maxRetrievals: 2, payloadId: "send-fields", digest: "zero" }],
  ["request-schema-passphrase", { contentMode: 2, factorMode: 1, clientNotAfter: 1800003600, maxRetrievals: 0, payloadId: "request-schema", digest: "payload" }],
  ["send-random-factor", { contentMode: 1, factorMode: 2, clientNotAfter: 1800003600, maxRetrievals: 3, payloadId: "send-fields", digest: "zero" }],
  ["request-schema-random-factor", { contentMode: 2, factorMode: 2, clientNotAfter: 1800003600, maxRetrievals: 0, payloadId: "request-schema", digest: "payload" }],
]);

const kxrScenario = {
  id: "request-response",
  suite: 1,
  flags: 0,
  reserved: 0,
  clientNotAfter: 1800003600,
  schemaPayloadId: "request-schema",
  payloadId: "request-response",
  encLength: 32,
};

const capabilityScenarios = new Map([
  ["send-retrieve-random-factor", { resourceKind: 1, capabilityKind: 1, locator: "send-2", token: "send-retrieve-2" }],
  ["send-manage", { resourceKind: 1, capabilityKind: 2, locator: "send-0", token: "send-manage-0" }],
  ["request-write-passphrase", { resourceKind: 2, capabilityKind: 1, locator: "request-1", token: "request-write-1" }],
  ["request-owner", { resourceKind: 2, capabilityKind: 2, locator: "request-0", token: "request-owner-0" }],
  ["create-permit", { resourceKind: 3, capabilityKind: 3, locator: "permit", token: "permit" }],
]);

const rateScenarios = new Map([
  ["send", { resourceKind: 1, locator: "send-0" }],
  ["request", { resourceKind: 2, locator: "request-0" }],
  ["create-permit", { resourceKind: 3, locator: "permit" }],
]);

function fail(code) {
  throw new Error(code);
}

function bytesFromHex(value) {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function hex(value) {
  return Buffer.from(value).toString("hex");
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function concatenate(...values) {
  const output = new Uint8Array(values.reduce((length, value) => length + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function bytesEqual(left, right, message) {
  equal(Buffer.from(left).equals(Buffer.from(right)), true, message);
}

function u16(value) {
  const output = new Uint8Array(2);
  new DataView(output.buffer).setUint16(0, value);
  return output;
}

function u32(value) {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value);
  return output;
}

function u64(value) {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value));
  return output;
}

function readSafeU64(bytes, offset) {
  const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail("unsafe_timestamp");
  return Number(value);
}

function pattern(offset, length) {
  return Uint8Array.from({ length }, (_, index) => (offset + index) & 0xff);
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

async function hmac(key, value) {
  const imported = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, value));
}

async function hkdfExtract(label, ikm) {
  return hmac(await sha256(encoder.encode(label)), ikm);
}

async function hkdf(label, ikm, outputLabel, bitLength) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: await sha256(encoder.encode(label)),
    info: encoder.encode(outputLabel),
  }, key, bitLength));
}

function decodeCanonicalBase64url(value) {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) fail("non_canonical_base64url");
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (base64url(decoded) !== value) fail("non_canonical_base64url");
  return decoded;
}

const base32Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function crockfordEncode(bytes) {
  let accumulator = 0;
  let bits = 0;
  let compact = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      compact += base32Alphabet[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits > 0) compact += base32Alphabet[(accumulator << (5 - bits)) & 31];
  return compact.match(/.{13}/g).join("-");
}

function decodeCrockford(value) {
  let compact = "";
  let lastWasHyphen = false;
  for (const character of value.toUpperCase()) {
    if (character === "-") {
      if (lastWasHyphen || ![13, 26, 39].includes(compact.length)) fail("invalid_random_factor");
      lastWasHyphen = true;
      continue;
    }
    compact += character;
    lastWasHyphen = false;
  }
  if (lastWasHyphen) fail("invalid_random_factor");
  compact = compact.replaceAll("O", "0").replaceAll("I", "1").replaceAll("L", "1");
  if (compact.length !== 52 || /[^0-9A-HJKMNP-TV-Z]/.test(compact) || compact.includes("U")) {
    fail("invalid_random_factor");
  }
  const output = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of compact) {
    const digit = base32Alphabet.indexOf(character);
    if (digit < 0) fail("invalid_random_factor");
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits !== 4 || accumulator !== 0 || output.length !== 32) fail("invalid_random_factor");
  return Uint8Array.from(output);
}

function rejectInvalidUnicode(value) {
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) fail("invalid_unicode");
        index += 1;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) fail("invalid_unicode");
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(rejectInvalidUnicode);
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      rejectInvalidUnicode(key);
      rejectInvalidUnicode(item);
    }
  }
}

function restrictedJcs(value) {
  rejectInvalidUnicode(value);
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(restrictedJcs).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${restrictedJcs(value[key])}`).join(",")}}`;
  }
  fail("forbidden_json_type");
}

function exactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (expected.some((key) => !actual.includes(key))) fail("missing_key");
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail("unexpected_key");
}

function utf8Length(value) {
  return encoder.encode(value).length;
}

function requireString(value, minimum, maximum, code) {
  if (typeof value !== "string" || utf8Length(value) < minimum || utf8Length(value) > maximum) fail(code);
}

function validateSchema(schema) {
  exactKeys(schema, ["fields", "kind", "recipientPublicKey", "title"]);
  if (schema.kind !== "request-schema") fail("invalid_kind");
  requireString(schema.title, 1, 120, "invalid_title");
  if (!Array.isArray(schema.fields) || schema.fields.length < 1 || schema.fields.length > 32) fail("invalid_field_count");
  const ids = new Set();
  for (const field of schema.fields) {
    exactKeys(field, ["help", "id", "label", "required", "type"]);
    requireString(field.help, 0, 500, "invalid_help");
    requireString(field.label, 1, 120, "invalid_label");
    if (typeof field.id !== "string" || !/^[a-z0-9]{8,32}$/.test(field.id)) fail("invalid_field_id");
    if (ids.has(field.id)) fail("duplicate_field_id");
    ids.add(field.id);
    if (typeof field.required !== "boolean" || !["short", "secret", "long", "instruction"].includes(field.type)) fail("invalid_field");
    if (field.type === "instruction" && field.required) fail("invalid_instruction");
  }
  if (typeof schema.recipientPublicKey !== "string" || decodeCanonicalBase64url(schema.recipientPublicKey).length !== 32) {
    fail("invalid_recipient_public_key");
  }
}

function validatePayload(value, expectedSchema) {
  restrictedJcs(value);
  if (value.kind === "text") {
    exactKeys(value, ["kind", "text"]);
    requireString(value.text, 1, 262144, "invalid_text");
    return;
  }
  if (value.kind === "fields") {
    exactKeys(value, ["fields", "kind"]);
    if (!Array.isArray(value.fields) || value.fields.length < 1 || value.fields.length > 32) fail("invalid_field_count");
    for (const field of value.fields) {
      exactKeys(field, ["concealed", "label", "value"]);
      if (typeof field.concealed !== "boolean") fail("invalid_concealed");
      requireString(field.label, 1, 120, "invalid_label");
      requireString(field.value, 1, 262144, "invalid_value");
    }
    return;
  }
  if (value.kind === "request-schema") {
    validateSchema(value);
    return;
  }
  if (value.kind === "request-response") {
    exactKeys(value, ["answers", "kind", "schema"]);
    validateSchema(value.schema);
    if (expectedSchema !== undefined && restrictedJcs(value.schema) !== restrictedJcs(expectedSchema)) fail("schema_mismatch");
    const fields = value.schema.fields.filter((field) => field.type !== "instruction");
    if (!Array.isArray(value.answers) || value.answers.length !== fields.length) fail("answer_count_mismatch");
    value.answers.forEach((answer, index) => {
      exactKeys(answer, ["id", "value"]);
      if (answer.id !== fields[index].id) fail("answer_order_mismatch");
      requireString(answer.value, 0, 262144, "invalid_value");
      if (fields[index].required && answer.value.length === 0) fail("required_answer_empty");
    });
    return;
  }
  fail("invalid_kind");
}

function duplicateRawKey(rawJson) {
  const keys = [...rawJson.matchAll(/"((?:\\.|[^"\\])*)"\s*:/g)].map((match) => match[1]);
  return new Set(keys).size !== keys.length;
}

function validateRawJson(rawJson) {
  if (duplicateRawKey(rawJson)) fail("duplicate_json_key");
  const value = JSON.parse(rawJson);
  rejectInvalidUnicode(value);
  if (restrictedJcs(value) !== rawJson) fail("non_canonical_json");
  validatePayload(value);
}

function chooseBucket(payloadLength) {
  const selected = bucketLengths.find((length) => payloadLength + 4 <= length);
  if (selected === undefined) fail("payload_too_large");
  return selected;
}

function buildPaddedPlaintext(payload, selectedBucket, paddingOffset) {
  if (payload.length + 4 > selectedBucket) fail("invalid_payload_length");
  return concatenate(u32(payload.length), payload, pattern(paddingOffset, selectedBucket - 4 - payload.length));
}

async function loadFixtures() {
  const manifest = JSON.parse(await readFile(resolve(vectorDirectory, "manifest.json"), "utf8"));
  const files = { "manifest.json": manifest };
  for (const filename of manifest.files) files[filename] = JSON.parse(await readFile(resolve(vectorDirectory, filename), "utf8"));
  return files;
}

function assertScenarioMetadata(fixtures) {
  const bundles = fixtures["bundles.json"].bundles;
  equal(bundles.length, bundleScenarios.size, "bundle scenario count");
  for (const vector of bundles) {
    const scenario = bundleScenarios.get(vector.id);
    if (scenario === undefined) fail("unknown_bundle_scenario");
    equal(vector.kind, scenario.kind, `bundle kind ${vector.id}`);
    equal(vector.bodyLength, scenario.bodyLength, `bundle body length ${vector.id}`);
    equal(vector.factorMode, scenario.factorMode, `bundle factor semantics ${vector.id}`);
  }
  const envelopes = fixtures["envelopes.json"];
  equal(envelopes.kxe1.length, kxeScenarios.size, "KXE scenario count");
  for (const vector of envelopes.kxe1) {
    const scenario = kxeScenarios.get(vector.id);
    if (scenario === undefined) fail("unknown_kxe_scenario");
    equal(vector.contentMode, scenario.contentMode, `KXE content mode ${vector.id}`);
    equal(vector.factorMode, scenario.factorMode, `KXE factor mode ${vector.id}`);
    equal(vector.clientNotAfter, scenario.clientNotAfter, `KXE timestamp ${vector.id}`);
    equal(vector.maxRetrievals, scenario.maxRetrievals, `KXE retrieval count ${vector.id}`);
    equal(vector.payloadId, scenario.payloadId, `KXE payload semantics ${vector.id}`);
  }
  const response = envelopes.kxr1;
  equal(response.id, kxrScenario.id, "KXR scenario ID");
  equal(response.clientNotAfter, kxrScenario.clientNotAfter, "KXR timestamp");
  equal(response.payloadId, kxrScenario.payloadId, "KXR payload semantics");
  const tags = fixtures["server-tags.json"];
  equal(tags.capabilityTags.length, capabilityScenarios.size, "capability scenario count");
  for (const vector of tags.capabilityTags) {
    const scenario = capabilityScenarios.get(vector.id);
    if (scenario === undefined) fail("unknown_capability_scenario");
    equal(vector.resourceKind, scenario.resourceKind, `capability resource kind ${vector.id}`);
    equal(vector.capabilityKind, scenario.capabilityKind, `capability kind ${vector.id}`);
  }
  equal(tags.rateLimitTags.length, rateScenarios.size, "rate scenario count");
  for (const vector of tags.rateLimitTags) {
    const scenario = rateScenarios.get(vector.id);
    if (scenario === undefined) fail("unknown_rate_scenario");
    equal(vector.resourceKind, scenario.resourceKind, `rate resource kind ${vector.id}`);
  }
}

async function deriveSchedules(fixtures) {
  const inputs = fixtures["manifest.json"].fixedInputs;
  const expected = fixtures["key-schedules.json"];
  const sendSeed = bytesFromHex(inputs.sendSeedHex);
  const manageSeed = bytesFromHex(inputs.manageSeedHex);
  const requestLocator = bytesFromHex(inputs.requestLocatorHex);
  const writeSeed = bytesFromHex(inputs.writeSeedHex);
  const ownerSeed = bytesFromHex(inputs.ownerSeedHex);
  const passphraseFactor = argon2id(encoder.encode(inputs.passphrase), bytesFromHex(inputs.passphraseSaltHex), {
    t: 3, m: 65536, p: 1, version: 19, dkLen: 32, maxmem: 128 * 1024 * 1024,
  });
  bytesEqual(passphraseFactor, bytesFromHex(expected.argon2id.outputHex), "Argon2id output");
  const factors = [new Uint8Array(32), passphraseFactor, bytesFromHex(inputs.randomFactorHex)];
  const modeNames = ["none", "passphrase", "random-factor"];
  const sends = [];
  const requests = [];
  for (const factorMode of [0, 1, 2]) {
    const locatorLabel = "kryptex/v1/send/locator";
    const masterLabel = `kryptex/v1/send/master/${modeNames[factorMode]}`;
    const manageLabel = "kryptex/v1/send/manage-token";
    const locatorPrk = await hkdfExtract(locatorLabel, sendSeed);
    const masterPrk = await hkdfExtract(masterLabel, concatenate(sendSeed, factors[factorMode]));
    const managePrk = await hkdfExtract(manageLabel, manageSeed);
    const send = {
      factorMode,
      factorModeName: modeNames[factorMode],
      factorHex: hex(factors[factorMode]),
      locatorPrkHex: hex(locatorPrk),
      locatorBase64url: base64url(await hkdf(locatorLabel, sendSeed, locatorLabel, 128)),
      masterPrkHex: hex(masterPrk),
      contentKeyHex: hex(await hkdf(masterLabel, concatenate(sendSeed, factors[factorMode]), "kryptex/v1/send/content-key", 256)),
      retrieveTokenBase64url: base64url(await hkdf(masterLabel, concatenate(sendSeed, factors[factorMode]), "kryptex/v1/send/retrieve-token", 256)),
      managePrkHex: hex(managePrk),
      manageTokenBase64url: base64url(await hkdf(manageLabel, manageSeed, manageLabel, 256)),
    };
    deepStrictEqual(send, expected.send[factorMode], `send key schedule mode ${factorMode}`);
    sends.push(send);
    const writeLabel = `kryptex/v1/request/write-master/${modeNames[factorMode]}`;
    const ownerLabel = "kryptex/v1/request/owner-token";
    const writePrk = await hkdfExtract(writeLabel, concatenate(writeSeed, factors[factorMode]));
    const ownerPrk = await hkdfExtract(ownerLabel, ownerSeed);
    const hpkeIkm = await hkdf(ownerLabel, ownerSeed, "kryptex/v1/request/hpke-keypair", 256);
    const keyPair = await suite.kem.deriveKeyPair(hpkeIkm);
    const publicKey = new Uint8Array(await suite.kem.serializePublicKey(keyPair.publicKey));
    const privateKey = new Uint8Array(await suite.kem.serializePrivateKey(keyPair.privateKey));
    const request = {
      factorMode,
      factorModeName: modeNames[factorMode],
      factorHex: hex(factors[factorMode]),
      requestLocatorBase64url: base64url(requestLocator),
      writePrkHex: hex(writePrk),
      schemaKeyHex: hex(await hkdf(writeLabel, concatenate(writeSeed, factors[factorMode]), "kryptex/v1/request/schema-key", 256)),
      writeTokenBase64url: base64url(await hkdf(writeLabel, concatenate(writeSeed, factors[factorMode]), "kryptex/v1/request/write-token", 256)),
      ownerPrkHex: hex(ownerPrk),
      ownerTokenBase64url: base64url(await hkdf(ownerLabel, ownerSeed, ownerLabel, 256)),
      hpkeIkmHex: hex(hpkeIkm),
      recipientPrivateKeyHex: hex(privateKey),
      recipientPublicKeyBase64url: base64url(publicKey),
    };
    deepStrictEqual(request, expected.request[factorMode], `request key schedule mode ${factorMode}`);
    requests.push(request);
  }
  return { sends, requests };
}

function buildBundle(kind, body) {
  return concatenate(encoder.encode("KXB1"), Uint8Array.of(kind, 1), u16(body.length), body);
}

function parseBundle(bytes) {
  if (bytes.length < 8 || decoder.decode(bytes.slice(0, 4)) !== "KXB1") fail("invalid_magic");
  const kind = bytes[4];
  const expectedLength = new Map([[1, 57], [2, 56], [3, 105], [4, 56]]).get(kind);
  if (expectedLength === undefined) fail("unsupported_kind");
  if (bytes[5] !== 1) fail("unsupported_version");
  const bodyLength = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(6);
  if (bytes.length > bodyLength + 8) fail("trailing_bytes");
  if (bodyLength !== expectedLength || bytes.length !== bodyLength + 8) fail("invalid_length");
  const factorOffset = kind === 1 ? 40 : kind === 3 ? 56 : undefined;
  if (factorOffset !== undefined) {
    if (bytes[factorOffset] > 2) fail("unsupported_factor_mode");
    if (bytes[factorOffset] !== 1 && bytes.slice(factorOffset + 1, factorOffset + 17).some((byte) => byte !== 0)) {
      fail("invalid_salt");
    }
  }
  readSafeU64(bytes, bytes.length - 8);
  return { kind, factorMode: factorOffset === undefined ? undefined : bytes[factorOffset], bytes };
}

function checkBundles(fixtures, schedules) {
  const inputs = fixtures["manifest.json"].fixedInputs;
  const expected = fixtures["bundles.json"].bundles;
  const sendSeed = bytesFromHex(inputs.sendSeedHex);
  const manageSeed = bytesFromHex(inputs.manageSeedHex);
  const locator = decodeCanonicalBase64url(schedules.sends[0].locatorBase64url);
  const requestLocator = bytesFromHex(inputs.requestLocatorHex);
  const writeSeed = bytesFromHex(inputs.writeSeedHex);
  const ownerSeed = bytesFromHex(inputs.ownerSeedHex);
  const publicKey = decodeCanonicalBase64url(schedules.requests[0].recipientPublicKeyBase64url);
  for (const vector of expected) {
    const scenario = bundleScenarios.get(vector.id);
    const expiry = u64(scenario.serverExpiresAt);
    let body;
    if (scenario.kind === 1) {
      const salt = scenario.factorMode === 1 ? bytesFromHex(inputs.passphraseSaltHex) : new Uint8Array(16);
      body = concatenate(sendSeed, Uint8Array.of(scenario.factorMode), salt, expiry);
    } else if (scenario.kind === 2) {
      body = concatenate(locator, manageSeed, expiry);
    } else if (scenario.kind === 3) {
      const salt = scenario.factorMode === 1 ? bytesFromHex(inputs.passphraseSaltHex) : new Uint8Array(16);
      body = concatenate(requestLocator, writeSeed, Uint8Array.of(scenario.factorMode), salt, publicKey, expiry);
    } else {
      body = concatenate(requestLocator, ownerSeed, expiry);
    }
    const built = buildBundle(scenario.kind, body);
    equal(base64url(built), vector.base64url, `bundle ${vector.id}`);
    equal(hex(built), vector.bytesHex, `bundle hex ${vector.id}`);
    parseBundle(built);
  }
}

function buildKxeHeader(contentMode, factorMode, clientNotAfter, maxRetrievals, digest, nonce) {
  return concatenate(
    encoder.encode("KXE1"),
    Uint8Array.of(1, contentMode, factorMode, 0),
    u64(clientNotAfter),
    u16(maxRetrievals),
    digest,
    nonce,
  );
}

async function aesEncrypt(keyBytes, nonce, aad, plaintext) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, plaintext));
}

async function aesDecrypt(keyBytes, nonce, aad, ciphertext) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, ciphertext));
}

async function checkJcs(fixtures) {
  const jcs = fixtures["jcs.json"];
  for (const vector of [...jcs.payloads, ...jcs.canonicalizationCases]) {
    const serialized = restrictedJcs(vector.object);
    equal(serialized, vector.jcs, `JCS ${vector.id}`);
    equal(hex(encoder.encode(serialized)), vector.utf8Hex, `JCS UTF-8 ${vector.id}`);
    equal(hex(await sha256(encoder.encode(serialized))), vector.sha256Hex, `JCS digest ${vector.id}`);
    if (jcs.payloads.includes(vector)) validatePayload(vector.object);
  }
  for (const vector of jcs.invalidJcsAndPayloads) {
    let result = "accepted";
    try {
      if (vector.rawJson !== undefined) validateRawJson(vector.rawJson);
      else if (vector.utf8Hex !== undefined) validateRawJson(decoder.decode(bytesFromHex(vector.utf8Hex)));
      else validatePayload(vector.object, vector.expectedSchema);
    } catch (error) {
      result = vector.utf8Hex === undefined ? error.message : "malformed_utf8";
    }
    equal(result, vector.error, `invalid JCS/payload ${vector.id}`);
  }
}

async function checkBoundaries(fixtures) {
  const boundaries = fixtures["boundaries.json"];
  deepStrictEqual(boundaries.allowedBucketLengths, bucketLengths, "bucket list");
  for (const vector of boundaries.cases) {
    let result;
    try {
      const selected = chooseBucket(vector.payloadLength);
      const payload = pattern(vector.payload.offset, vector.payloadLength);
      const plaintext = buildPaddedPlaintext(payload, selected, vector.padding.offset);
      result = {
        selected,
        plaintextLength: plaintext.length,
        plaintextSha256Hex: hex(await sha256(plaintext)),
        kxeEnvelopeLength: 62 + plaintext.length + 16,
        kxrEnvelopeLength: 86 + plaintext.length + 16,
      };
    } catch (error) {
      result = { error: error.message };
    }
    if (vector.error !== undefined) {
      deepStrictEqual(result, { error: vector.error }, `boundary ${vector.id}`);
    } else {
      equal(result.selected, vector.expectedBucketLength, `selected bucket ${vector.id}`);
      equal(result.plaintextLength, vector.plaintextLength, `plaintext length ${vector.id}`);
      equal(result.plaintextSha256Hex, vector.plaintextSha256Hex, `plaintext hash ${vector.id}`);
      equal(result.kxeEnvelopeLength, vector.kxeEnvelopeLength, `KXE length ${vector.id}`);
      equal(result.kxrEnvelopeLength, vector.kxrEnvelopeLength, `KXR length ${vector.id}`);
    }
  }
}

async function checkEnvelopes(fixtures, schedules) {
  const inputs = fixtures["manifest.json"].fixedInputs;
  const envelopes = fixtures["envelopes.json"];
  const fixtureBucket = 4096;
  equal(envelopes.fixtureBucketLength, fixtureBucket, "fixture bucket length");
  const payloads = new Map(fixtures["jcs.json"].payloads.map((entry) => [entry.id, entry]));
  for (const vector of envelopes.kxe1) {
    const scenario = kxeScenarios.get(vector.id);
    const payload = payloads.get(scenario.payloadId);
    const payloadBytes = encoder.encode(restrictedJcs(payload.object));
    const plaintext = buildPaddedPlaintext(payloadBytes, fixtureBucket, vector.padding.offset);
    const digest = scenario.digest === "zero" ? new Uint8Array(32) : await sha256(payloadBytes);
    equal(hex(digest), vector.schemaDigestHex, `KXE digest metadata ${vector.id}`);
    const nonce = bytesFromHex(vector.nonceHex);
    const header = buildKxeHeader(
      scenario.contentMode,
      scenario.factorMode,
      scenario.clientNotAfter,
      scenario.maxRetrievals,
      digest,
      nonce,
    );
    const keyHex = scenario.contentMode === 1
      ? schedules.sends[scenario.factorMode].contentKeyHex
      : schedules.requests[scenario.factorMode].schemaKeyHex;
    const ciphertext = await aesEncrypt(bytesFromHex(keyHex), nonce, header, plaintext);
    const envelope = concatenate(header, ciphertext);
    equal(base64url(envelope), vector.envelopeBase64url, `KXE ${vector.id}`);
    equal(plaintext.length, vector.plaintextLength, `KXE plaintext length ${vector.id}`);
    equal(envelope.length, vector.envelopeLength, `KXE envelope length ${vector.id}`);
    equal(hex(await sha256(plaintext)), vector.plaintextSha256Hex, `KXE plaintext hash ${vector.id}`);
    equal(hex(await sha256(envelope)), vector.envelopeSha256Hex, `KXE hash ${vector.id}`);
    if (scenario.contentMode === 2) bytesEqual(await sha256(payloadBytes), digest, `schema digest ${vector.id}`);
  }
  const response = envelopes.kxr1;
  const schema = payloads.get(kxrScenario.schemaPayloadId);
  const responsePayload = payloads.get(kxrScenario.payloadId);
  const schemaDigest = await sha256(encoder.encode(restrictedJcs(schema.object)));
  const info = concatenate(encoder.encode("kryptex/v1/request/response"), bytesFromHex(inputs.requestLocatorHex), schemaDigest);
  equal(hex(info), response.infoHex, "KXR info");
  const recipientKeyPair = await suite.kem.deriveKeyPair(bytesFromHex(schedules.requests[0].hpkeIkmHex));
  const sender = await suite.createSenderContext({
    recipientPublicKey: recipientKeyPair.publicKey,
    info,
    ekm: bytesFromHex(inputs.hpkeEphemeralIkmHex),
  });
  const enc = new Uint8Array(sender.enc);
  equal(hex(enc), response.encHex, "KXR encapsulated key");
  const plaintext = buildPaddedPlaintext(encoder.encode(restrictedJcs(responsePayload.object)), fixtureBucket, response.padding.offset);
  const aad = concatenate(
    encoder.encode("KXR1"), Uint8Array.of(kxrScenario.suite, kxrScenario.flags), u16(kxrScenario.reserved),
    u64(kxrScenario.clientNotAfter), schemaDigest, u16(kxrScenario.encLength), u32(plaintext.length + 16), enc,
  );
  equal(hex(aad), response.aadHex, "KXR AAD");
  const ciphertext = new Uint8Array(await sender.seal(plaintext, aad));
  const envelope = concatenate(aad, ciphertext);
  equal(base64url(envelope), response.envelopeBase64url, "KXR envelope");
  equal(plaintext.length, response.plaintextLength, "KXR plaintext length");
  equal(ciphertext.length, response.ciphertextLength, "KXR ciphertext length");
  equal(envelope.length, response.envelopeLength, "KXR envelope length");
  const receipt = await sha256(envelope);
  equal(base64url(receipt), response.receiptBase64url, "KXR receipt encoding");
  equal(hex(receipt), response.envelopeSha256Hex, "KXR receipt digest");
  equal(hex(receipt).toUpperCase().match(/.{8}/g).join(" "), response.receiptDisplay, "KXR receipt display");
}

async function checkServerTags(fixtures, schedules) {
  const inputs = fixtures["manifest.json"].fixedInputs;
  const tags = fixtures["server-tags.json"];
  const issuanceInput = concatenate(
    encoder.encode("kryptex/v1/create-permit/issuance"), Uint8Array.of(0), bytesFromHex(inputs.permitRequestIdHex),
  );
  const permitSeed = await hmac(bytesFromHex(inputs.permitIssuanceKeyHex), issuanceInput);
  const permitPrk = await hkdfExtract("kryptex/v1/create-permit/locator", permitSeed);
  const permitLocator = await hkdf("kryptex/v1/create-permit/locator", permitSeed, "kryptex/v1/create-permit/locator", 128);
  const permitToken = await hkdf("kryptex/v1/create-permit/locator", permitSeed, "kryptex/v1/create-permit/token", 256);
  equal(hex(permitSeed), tags.createPermit.permitSeedHex, "permit issuance");
  equal(hex(permitPrk), tags.createPermit.permitPrkHex, "permit PRK");
  equal(base64url(permitLocator), tags.createPermit.permitLocatorBase64url, "permit locator");
  equal(base64url(permitToken), tags.createPermit.permitTokenBase64url, "permit token");
  equal(tags.serverKeyHex, inputs.serverHmacKeyHex, "server tag key input");
  equal(tags.rateLimitKeyHex, inputs.rateLimitHmacKeyHex, "rate tag key input");
  const capabilityValues = new Map([
    ["send-0", schedules.sends[0].locatorBase64url],
    ["send-2", schedules.sends[2].locatorBase64url],
    ["send-retrieve-2", schedules.sends[2].retrieveTokenBase64url],
    ["send-manage-0", schedules.sends[0].manageTokenBase64url],
    ["request-0", schedules.requests[0].requestLocatorBase64url],
    ["request-1", schedules.requests[1].requestLocatorBase64url],
    ["request-write-1", schedules.requests[1].writeTokenBase64url],
    ["request-owner-0", schedules.requests[0].ownerTokenBase64url],
    ["permit", base64url(permitLocator)],
  ]);
  for (const vector of tags.capabilityTags) {
    const scenario = capabilityScenarios.get(vector.id);
    const expectedLocator = capabilityValues.get(scenario.locator);
    const expectedToken = scenario.token === "permit" ? base64url(permitToken) : capabilityValues.get(scenario.token);
    deepStrictEqual(
      [vector.locatorBase64url, vector.tokenBase64url],
      [expectedLocator, expectedToken],
      `capability inputs ${vector.id}`,
    );
    const input = concatenate(
      encoder.encode("kryptex/v1/server-capability-tag"), Uint8Array.of(0, scenario.resourceKind, scenario.capabilityKind),
      decodeCanonicalBase64url(expectedLocator), decodeCanonicalBase64url(expectedToken),
    );
    equal(hex(await hmac(bytesFromHex(inputs.serverHmacKeyHex), input)), vector.tagHex, `capability tag ${vector.id}`);
  }
  for (const vector of tags.rateLimitTags) {
    const scenario = rateScenarios.get(vector.id);
    const expectedLocator = capabilityValues.get(scenario.locator);
    equal(vector.locatorBase64url, expectedLocator, `rate locator ${vector.id}`);
    const input = concatenate(
      encoder.encode("kryptex/v1/rate-limit-locator"), Uint8Array.of(0, scenario.resourceKind),
      decodeCanonicalBase64url(expectedLocator),
    );
    equal(base64url(await hmac(bytesFromHex(inputs.rateLimitHmacKeyHex), input)), vector.tagBase64url, `rate tag ${vector.id}`);
  }
  notEqual(schedules.sends[0].manageTokenBase64url, schedules.sends[0].retrieveTokenBase64url);
  notEqual(schedules.requests[0].ownerTokenBase64url, schedules.requests[0].writeTokenBase64url);
}

async function validateKxe(bytes, keyHex) {
  if (bytes.length < 62 || decoder.decode(bytes.slice(0, 4)) !== "KXE1") fail("invalid_magic");
  if (bytes[4] !== 1) fail("unsupported_suite");
  if (![1, 2].includes(bytes[5])) fail("unsupported_content_mode");
  if (bytes[6] > 2) fail("unsupported_factor_mode");
  if (bytes[7] !== 0) fail("reserved_bits");
  readSafeU64(bytes, 8);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const retrievals = view.getUint16(16);
  const digest = bytes.slice(18, 50);
  if (bytes[5] === 1) {
    if (retrievals < 1 || retrievals > 10) fail("invalid_retrieval_count");
    if (digest.some((byte) => byte !== 0)) fail("invalid_schema_digest");
  } else if (retrievals !== 0) fail("invalid_retrieval_count");
  const plaintextLength = bytes.length - 62 - 16;
  if (!bucketLengths.includes(plaintextLength)) fail("invalid_length");
  if (keyHex === undefined) return;
  const plaintext = await aesDecrypt(bytesFromHex(keyHex), bytes.slice(50, 62), bytes.slice(0, 62), bytes.slice(62));
  const payloadLength = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength).getUint32(0);
  if (payloadLength + 4 > plaintext.length) fail("invalid_payload_length");
  if (chooseBucket(payloadLength) !== plaintext.length) fail("nonminimal_bucket");
  if (bytes[5] === 2) {
    const payload = plaintext.slice(4, 4 + payloadLength);
    if (hex(await sha256(payload)) !== hex(digest)) fail("schema_digest_mismatch");
  }
}

function validateKxr(bytes) {
  if (bytes.length < 86 || decoder.decode(bytes.slice(0, 4)) !== "KXR1") fail("invalid_magic");
  if (bytes[4] !== 1) fail("unsupported_suite");
  if (bytes[5] !== 0 || bytes[6] !== 0 || bytes[7] !== 0) fail("reserved_bits");
  readSafeU64(bytes, 8);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const encLength = view.getUint16(48);
  if (encLength !== 32) fail("invalid_enc_length");
  const ciphertextLength = view.getUint32(50);
  const declaredLength = 54 + encLength + ciphertextLength;
  if (bytes.length > declaredLength) fail("trailing_bytes");
  if (bytes.length !== declaredLength || !bucketLengths.includes(ciphertextLength - 16)) fail("invalid_length");
}

async function validateMalformed(fixtures, schedules) {
  const encoding = fixtures["encoding.json"];
  for (const vector of encoding.base64url) {
    bytesEqual(decodeCanonicalBase64url(vector.canonical), bytesFromHex(vector.bytesHex), `base64url ${vector.id}`);
  }
  const factor = encoding.crockfordBase32;
  equal(crockfordEncode(bytesFromHex(factor.bytesHex)), factor.canonicalDisplay, "Crockford canonical display");
  for (const value of [factor.canonicalDisplay, factor.acceptedAliasDisplay, ...factor.acceptedHyphenVariants]) {
    bytesEqual(decodeCrockford(value), bytesFromHex(factor.bytesHex), `accepted Crockford form ${value}`);
  }
  const negative = fixtures["negative.json"];
  for (const vector of negative.malformedExternalEncodings) {
    let result = "accepted";
    try {
      if (vector.kind === "base64url") decodeCanonicalBase64url(vector.value);
      else decodeCrockford(vector.value);
    } catch (error) {
      result = error.message;
    }
    equal(result, vector.error, `malformed encoding ${vector.id}`);
  }
  for (const vector of negative.malformedContainers) {
    let result = "accepted";
    try {
      const bytes = decodeCanonicalBase64url(vector.valueBase64url);
      if (vector.container === "KXB1") parseBundle(bytes);
      else if (vector.container === "KXE1") {
        const keyHex = vector.keySource === undefined
          ? undefined
          : vector.keySource.startsWith("send")
            ? schedules.sends[0].contentKeyHex
            : schedules.requests[0].schemaKeyHex;
        await validateKxe(bytes, keyHex);
      } else validateKxr(bytes);
    } catch (error) {
      result = error.message;
    }
    equal(result, vector.error, `malformed container ${vector.id}`);
  }
}

async function validateWrongFactors(fixtures, schedules) {
  const negative = fixtures["negative.json"];
  const envelopes = fixtures["envelopes.json"].kxe1;
  const cases = [
    ["send-passphrase", "send-passphrase", "wrongContentKeyHex", "contentKeyHex", schedules.sends[1]],
    ["send-random-factor", "send-random-factor", "wrongContentKeyHex", "contentKeyHex", schedules.sends[2]],
    ["request-passphrase", "request-schema-passphrase", "wrongSchemaKeyHex", "schemaKeyHex", schedules.requests[1]],
    ["request-random-factor", "request-schema-random-factor", "wrongSchemaKeyHex", "schemaKeyHex", schedules.requests[2]],
  ];
  for (const [wrongId, envelopeId, wrongKeyProperty, correctKeyProperty, schedule] of cases) {
    const wrong = negative.wrongFactors.find((entry) => entry.id === wrongId);
    const vector = envelopes.find((entry) => entry.id === envelopeId);
    const envelope = decodeCanonicalBase64url(vector.envelopeBase64url);
    const factorModeName = wrongId.endsWith("passphrase") ? "passphrase" : "random-factor";
    const masterPrefix = wrongId.startsWith("send") ? "send/master" : "request/write-master";
    const seed = wrongId.startsWith("send")
      ? bytesFromHex(fixtures["manifest.json"].fixedInputs.sendSeedHex)
      : bytesFromHex(fixtures["manifest.json"].fixedInputs.writeSeedHex);
    const keyLabel = wrongId.startsWith("send") ? "kryptex/v1/send/content-key" : "kryptex/v1/request/schema-key";
    const tokenLabel = wrongId.startsWith("send") ? "kryptex/v1/send/retrieve-token" : "kryptex/v1/request/write-token";
    const masterInput = concatenate(seed, bytesFromHex(wrong.wrongFactorHex));
    const masterLabel = `kryptex/v1/${masterPrefix}/${factorModeName}`;
    const wrongKey = await hkdf(masterLabel, masterInput, keyLabel, 256);
    const wrongToken = await hkdf(masterLabel, masterInput, tokenLabel, 256);
    equal(hex(wrongKey), wrong[wrongKeyProperty], `wrong key derivation ${wrongId}`);
    equal(base64url(wrongToken), wrong.wrongTokenBase64url, `wrong token derivation ${wrongId}`);
    notEqual(base64url(wrongToken), wrong.correctTokenBase64url, `wrong authorization ${wrongId}`);
    notEqual(hex(wrongKey), schedule[correctKeyProperty], `wrong decryption key ${wrongId}`);
    await rejects(aesDecrypt(wrongKey, envelope.slice(50, 62), envelope.slice(0, 62), envelope.slice(62)));
  }
}

async function validateCrossContainerMismatches(fixtures) {
  const bundles = new Map(fixtures["bundles.json"].bundles.map((entry) => [entry.id, decodeCanonicalBase64url(entry.base64url)]));
  const envelopes = new Map(fixtures["envelopes.json"].kxe1.map((entry) => [entry.id, decodeCanonicalBase64url(entry.envelopeBase64url)]));
  const schemaVector = fixtures["jcs.json"].payloads.find((entry) => entry.id === "request-schema");
  const schema = schemaVector.object;
  const schemaDigest = await sha256(encoder.encode(restrictedJcs(schema)));
  for (const vector of fixtures["negative.json"].crossContainerMismatches) {
    let result = "accepted";
    try {
      if (vector.id === "recipient-factor-vs-send-envelope") {
        const bundle = parseBundle(bundles.get(vector.left));
        if (bundle.factorMode !== envelopes.get(vector.right)[6]) fail("factor_mode_mismatch");
      } else if (vector.id === "write-factor-vs-schema-envelope") {
        const bundle = parseBundle(bundles.get(vector.left));
        if (bundle.factorMode !== envelopes.get(vector.right)[6]) fail("factor_mode_mismatch");
      } else if (vector.id === "write-public-key-vs-schema") {
        const bundle = parseBundle(decodeCanonicalBase64url(vector.valueBase64url));
        if (base64url(bundle.bytes.slice(73, 105)) !== schema.recipientPublicKey) fail("recipient_public_key_mismatch");
      } else if (vector.id === "response-schema-digest-vs-schema") {
        const response = decodeCanonicalBase64url(vector.valueBase64url);
        if (hex(response.slice(16, 48)) !== hex(schemaDigest)) fail("schema_digest_mismatch");
      } else if (vector.id === "response-expiry-vs-schema") {
        const response = decodeCanonicalBase64url(vector.valueBase64url);
        const schemaEnvelope = fixtures["envelopes.json"].kxe1.find((entry) => entry.id === "request-schema-none");
        if (readSafeU64(response, 8) !== schemaEnvelope.clientNotAfter) fail("client_not_after_mismatch");
      } else if (vector.id === "response-at-kxe-endpoint") {
        const bytes = decodeCanonicalBase64url(vector.valueBase64url);
        if (decoder.decode(bytes.slice(0, 4)) !== "KXE1") fail("invalid_magic");
      } else if (vector.id === "send-at-kxr-endpoint") {
        const bytes = decodeCanonicalBase64url(vector.valueBase64url);
        if (decoder.decode(bytes.slice(0, 4)) !== "KXR1") fail("invalid_magic");
      } else fail("unknown_cross_container_case");
    } catch (error) {
      result = error.message;
    }
    equal(result, vector.error, `cross-container mismatch ${vector.id}`);
  }
}

async function validateRfc9180() {
  const rfc = {
    infoHex: "4f6465206f6e2061204772656369616e2055726e",
    ikmRHex: "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee",
    ikmEHex: "2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9",
    recipientPublicKeyHex: "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
    ephemeralPublicKeyHex: "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
    aadHex: "436f756e742d30",
    plaintextHex: "4265617574792069732074727574682c20747275746820626561757479",
    ciphertextHex: "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
  };
  const recipient = await suite.kem.deriveKeyPair(bytesFromHex(rfc.ikmRHex));
  bytesEqual(await suite.kem.serializePublicKey(recipient.publicKey), bytesFromHex(rfc.recipientPublicKeyHex), "RFC recipient key");
  const sender = await suite.createSenderContext({
    recipientPublicKey: recipient.publicKey,
    info: bytesFromHex(rfc.infoHex),
    ekm: bytesFromHex(rfc.ikmEHex),
  });
  bytesEqual(sender.enc, bytesFromHex(rfc.ephemeralPublicKeyHex), "RFC encapsulated key");
  bytesEqual(
    await sender.seal(bytesFromHex(rfc.plaintextHex), bytesFromHex(rfc.aadHex)),
    bytesFromHex(rfc.ciphertextHex),
    "RFC ciphertext",
  );
}

const fixtures = await loadFixtures();
assertScenarioMetadata(fixtures);
const schedules = await deriveSchedules(fixtures);
await checkJcs(fixtures);
await checkBoundaries(fixtures);
checkBundles(fixtures, schedules);
await checkEnvelopes(fixtures, schedules);
await checkServerTags(fixtures, schedules);
await validateMalformed(fixtures, schedules);
await validateWrongFactors(fixtures, schedules);
await validateCrossContainerMismatches(fixtures);
await validateRfc9180();

console.log(`Independently validated ${fixtures["manifest.json"].files.length + 1} static protocol vector files`);
