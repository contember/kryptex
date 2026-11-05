import { parseKxe1Envelope, parseKxr1Envelope } from "./envelopes.js";
import {
  DEVICE_QUOTA_PER_DAY,
  DEVICE_QUOTA_WINDOW_HOURS,
  FAILED_ACCESS_SATURATION,
  isDeviceGrantDays,
  isTtlSeconds,
  type DeviceGrantDays,
  type TtlSeconds
} from "./protocol.js";
import { parseJsonWithoutDuplicateKeys } from "./json.js";
import {
  ContractValidationError,
  expectArray,
  expectCanonicalBase64UrlLength,
  expectExactObject,
  expectIntegerInRange,
  expectSafeInteger,
  expectString,
  expectUtf8Length,
  readProperty
} from "./validation.js";

export type SendState = "active" | "exhausted" | "revoked" | "expired";
export type RequestState = "waiting" | "submitted" | "picked_up" | "revoked" | "expired";
export type PermitState = "unused";
export type ApiErrorCode =
  | "unavailable"
  | "rate_limited"
  | "invalid_request"
  | "forbidden"
  | "creation_permit_required"
  | "internal_error"
  | "gate_failed"
  | "gate_unavailable"
  | "quota_exhausted";

export interface CreatePermitRequest {
  readonly requestId: string;
  readonly turnstileResponse: string;
}

export interface CreatePermitResponse {
  readonly permitExpiresAt: number;
  readonly serverTime: number;
}

export interface CreatePermitStatusResponse extends CreatePermitResponse {
  readonly state: PermitState;
}

export interface SendCreateRequest {
  readonly attemptId: string;
  readonly clientNotAfter: number;
  readonly envelope: string;
  readonly locator: string;
  readonly manageToken: string;
  readonly maxRetrievals: number;
  readonly retrieveToken: string;
  readonly settleNotAfter: number;
  readonly ttlSeconds: TtlSeconds;
}

export interface RequestCreateRequest {
  readonly attemptId: string;
  readonly clientNotAfter: number;
  readonly envelope: string;
  readonly locator: string;
  readonly ownerToken: string;
  readonly settleNotAfter: number;
  readonly ttlSeconds: TtlSeconds;
  readonly writeToken: string;
}

export interface CreateResourceResponse {
  readonly serverExpiresAt: number;
}

export interface SendRetrieveRequest {
  readonly locator: string;
  readonly retrieveToken: string;
}

export interface SendManageRequest {
  readonly locator: string;
  readonly manageToken: string;
}

export interface SendShortenRequest extends SendManageRequest {
  readonly serverExpiresAt: number;
}

export interface SendStatusResponse {
  readonly failedAccessAttempts: number;
  readonly releasedAt: readonly number[];
  readonly remainingRetrievals: number;
  readonly serverExpiresAt: number;
  readonly state: SendState;
}

export interface RevokeResponse {
  readonly state: "revoked";
}

export interface ShortenResponse {
  readonly serverExpiresAt: number;
}

export interface RequestWriteRequest {
  readonly locator: string;
  readonly writeToken: string;
}

export interface RequestSubmitRequest extends RequestWriteRequest {
  readonly envelope: string;
}

export interface RequestOwnerRequest {
  readonly locator: string;
  readonly ownerToken: string;
}

export interface RequestShortenRequest extends RequestOwnerRequest {
  readonly serverExpiresAt: number;
}

export interface RequestSubmitResponse {
  readonly receipt: string;
}

export interface RequestStatusResponse {
  readonly serverExpiresAt: number;
  readonly state: RequestState;
}

export interface PairingStartRequest {
  readonly pollToken: string;
}

export interface PairingStartResponse {
  readonly pairingExpiresAt: number;
  readonly serverTime: number;
  readonly userCode: string;
}

export interface PairingApproveRequest {
  readonly requestId: string;
  readonly turnstileResponse: string;
  readonly userCode: string;
}

export interface PairingApproveResponse {
  readonly state: "approved";
}

export interface PairingRedeemRequest {
  readonly pollToken: string;
  readonly userCode: string;
}

export type PairingRedeemResponse =
  | { readonly pairingExpiresAt: number; readonly state: "pending" }
  | { readonly permit: string; readonly permitExpiresAt: number; readonly serverTime: number; readonly state: "approved" };

export interface DevicePairingStartRequest {
  readonly deviceLocator: string;
  readonly deviceToken: string;
  readonly maxDays: DeviceGrantDays;
}

export type DevicePairingStartResponse = PairingStartResponse;
export type DevicePairingApproveRequest = PairingApproveRequest;
export type DevicePairingApproveResponse = PairingApproveResponse;

export interface DevicePairingClaimStatusResponse {
  readonly maxDays: DeviceGrantDays;
  readonly pairingExpiresAt: number;
}

export type DevicePairingClaimRequest =
  | { readonly scope: "transfer" }
  | { readonly days: DeviceGrantDays; readonly manageToken: string; readonly scope: "device" };

export type DevicePairingClaimResponse =
  | { readonly scope: "transfer" }
  | { readonly deviceExpiresAt: number; readonly deviceLocator: string; readonly scope: "device" };

export interface DevicePairingRedeemRequest {
  readonly deviceToken: string;
  readonly userCode: string;
}

export type DevicePairingRedeemResponse =
  | { readonly pairingExpiresAt: number; readonly state: "pending" }
  | { readonly permit: string; readonly permitExpiresAt: number; readonly serverTime: number; readonly state: "transfer" }
  | { readonly deviceExpiresAt: number; readonly state: "device" };

export interface DevicePermitRequest {
  readonly deviceLocator: string;
  readonly deviceToken: string;
  readonly requestId: string;
}

export interface DevicePermitResponse {
  readonly permit: string;
  readonly permitExpiresAt: number;
  readonly serverTime: number;
}

/** Either the client's device token or the person's management token authorizes status and revocation. */
export type DeviceAccessRequest =
  | { readonly deviceLocator: string; readonly deviceToken: string }
  | { readonly deviceLocator: string; readonly manageToken: string };

export type DeviceState = "active" | "revoked";

export interface DeviceStatusResponse {
  readonly expiresAt: number;
  readonly hourlyMints: readonly number[];
  readonly quotaRemaining: number;
  readonly state: DeviceState;
}

export interface ApiErrorResponse {
  readonly error: ApiErrorCode;
}

export interface SendRetrieveMetadata {
  readonly remainingReleases: number;
  readonly serverExpiresAt: number;
}

export interface RequestSchemaMetadata {
  readonly serverExpiresAt: number;
}

export interface RequestPickupMetadata extends RequestSchemaMetadata {
  readonly receipt: string;
}

export interface ServerTimeMetadata {
  readonly serverTime: number;
}

export interface StateCheckedMetadata {
  readonly stateCheckedAt: number;
}

export function parseApiJsonText<T>(text: string, parser: (value: unknown) => T): T {
  return parser(parseJsonWithoutDuplicateKeys(text));
}

function parseEmpty(value: unknown): Record<string, never> {
  expectExactObject(value, [], "empty request");
  return {};
}

function parseTimestamp(value: unknown, context: string): number {
  return expectSafeInteger(value, context);
}

function parseTtl(value: unknown, context: string): TtlSeconds {
  const integer = expectSafeInteger(value, context);
  if (!isTtlSeconds(integer)) {
    throw new ContractValidationError(`${context} is not an allowed TTL`);
  }
  return integer;
}

function parseSendState(value: unknown, context: string): SendState {
  if (value === "active" || value === "exhausted" || value === "revoked" || value === "expired") {
    return value;
  }
  throw new ContractValidationError(`${context} is not a send state`);
}

function parseRequestState(value: unknown, context: string): RequestState {
  if (value === "waiting" || value === "submitted" || value === "picked_up" || value === "revoked" || value === "expired") {
    return value;
  }
  throw new ContractValidationError(`${context} is not a request state`);
}

function parseErrorCode(value: unknown): ApiErrorCode {
  if (
    value === "unavailable" ||
    value === "rate_limited" ||
    value === "invalid_request" ||
    value === "forbidden" ||
    value === "creation_permit_required" ||
    value === "internal_error" ||
    value === "gate_failed" ||
    value === "gate_unavailable" ||
    value === "quota_exhausted"
  ) {
    return value;
  }
  throw new ContractValidationError("error is not an API error code");
}

function parseLocator(value: unknown, context: string): string {
  return expectCanonicalBase64UrlLength(value, 16, context);
}

function parseToken(value: unknown, context: string): string {
  return expectCanonicalBase64UrlLength(value, 32, context);
}

function parseAttempt(value: unknown, context: string): string {
  return expectCanonicalBase64UrlLength(value, 16, context);
}

function parseRequestId(value: unknown): string {
  const requestId = expectString(value, "requestId");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId)) {
    throw new ContractValidationError("requestId must be a canonical lowercase UUID v4");
  }
  return requestId;
}

function parseTurnstileResponse(value: unknown): string {
  return expectUtf8Length(value, 1, 2048, "turnstileResponse");
}

export function parseCreatePermitRequest(value: unknown): CreatePermitRequest {
  const object = expectExactObject(value, ["requestId", "turnstileResponse"], "create permit request");
  return {
    requestId: parseRequestId(readProperty(object, "requestId", "create permit request")),
    turnstileResponse: parseTurnstileResponse(readProperty(object, "turnstileResponse", "create permit request"))
  };
}

export function parseCreatePermitRequestJson(text: string): CreatePermitRequest {
  return parseApiJsonText(text, parseCreatePermitRequest);
}

const USER_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Encodes the 5 random pairing-code bytes as the canonical `XXXX-XXXX` display form. */
export function encodeUserCode(bytes: Uint8Array): string {
  if (bytes.byteLength !== 5) {
    throw new ContractValidationError("user code must encode 5 bytes");
  }
  let accumulator = 0n;
  for (const byte of bytes) {
    accumulator = (accumulator << 8n) | BigInt(byte);
  }
  let compact = "";
  for (let shift = 35n; shift >= 0n; shift -= 5n) {
    compact += USER_CODE_ALPHABET[Number((accumulator >> shift) & 31n)] ?? "";
  }
  return `${compact.slice(0, 4)}-${compact.slice(4)}`;
}

export function decodeUserCode(code: string): Uint8Array<ArrayBuffer> {
  if (!/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/.test(code)) {
    throw new ContractValidationError("user code is not canonical");
  }
  let accumulator = 0n;
  for (const character of code.replace("-", "")) {
    accumulator = (accumulator << 5n) | BigInt(USER_CODE_ALPHABET.indexOf(character));
  }
  const bytes = new Uint8Array(5);
  for (let index = 4; index >= 0; index -= 1) {
    bytes[index] = Number(accumulator & 0xffn);
    accumulator >>= 8n;
  }
  return bytes;
}

/** Applies the second-key input rules to a typed or pasted code; returns the canonical form or null. */
export function normalizeUserCodeInput(input: string): string | null {
  if (!input.isWellFormed() || /\s/u.test(input)) {
    return null;
  }
  const upper = input.toUpperCase();
  const compact = upper.length === 9 && upper[4] === "-" ? upper.slice(0, 4) + upper.slice(5) : upper;
  const mapped = compact.replaceAll("O", "0").replaceAll("I", "1").replaceAll("L", "1");
  if (!/^[0-9A-HJKMNP-TV-Z]{8}$/.test(mapped)) {
    return null;
  }
  return `${mapped.slice(0, 4)}-${mapped.slice(4)}`;
}

function parseUserCode(value: unknown, context: string): string {
  const code = expectString(value, context);
  decodeUserCode(code);
  return code;
}

function parsePermitValue(value: unknown, context: string, prefix: "v2." | "v3." = "v2."): string {
  const permit = expectString(value, context);
  if (!permit.startsWith(prefix)) {
    throw new ContractValidationError(`${context} is not a ${prefix} permit`);
  }
  expectCanonicalBase64UrlLength(permit.slice(3), 32, context);
  return permit;
}

function parseDeviceGrantDays(value: unknown, context: string): DeviceGrantDays {
  const days = expectSafeInteger(value, context);
  if (!isDeviceGrantDays(days)) {
    throw new ContractValidationError(`${context} is not an allowed device grant lifetime`);
  }
  return days;
}

function isObjectWithKeyCount(value: unknown, count: number): boolean {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).length === count;
}

function hasKey(value: unknown, key: string): boolean {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.hasOwn(value, key);
}

export function parsePairingStartRequest(value: unknown): PairingStartRequest {
  const context = "pairing start request";
  const object = expectExactObject(value, ["pollToken"], context);
  return { pollToken: parseToken(readProperty(object, "pollToken", context), `${context}.pollToken`) };
}

export function parsePairingStartRequestJson(text: string): PairingStartRequest {
  return parseApiJsonText(text, parsePairingStartRequest);
}

export function parsePairingApproveRequest(value: unknown): PairingApproveRequest {
  const context = "pairing approve request";
  const object = expectExactObject(value, ["requestId", "turnstileResponse", "userCode"], context);
  return {
    requestId: parseRequestId(readProperty(object, "requestId", context)),
    turnstileResponse: parseTurnstileResponse(readProperty(object, "turnstileResponse", context)),
    userCode: parseUserCode(readProperty(object, "userCode", context), `${context}.userCode`)
  };
}

export function parsePairingApproveRequestJson(text: string): PairingApproveRequest {
  return parseApiJsonText(text, parsePairingApproveRequest);
}

export function parsePairingRedeemRequest(value: unknown): PairingRedeemRequest {
  const context = "pairing redeem request";
  const object = expectExactObject(value, ["pollToken", "userCode"], context);
  return {
    pollToken: parseToken(readProperty(object, "pollToken", context), `${context}.pollToken`),
    userCode: parseUserCode(readProperty(object, "userCode", context), `${context}.userCode`)
  };
}

export function parsePairingRedeemRequestJson(text: string): PairingRedeemRequest {
  return parseApiJsonText(text, parsePairingRedeemRequest);
}

export function parsePairingStartResponse(value: unknown): PairingStartResponse {
  const context = "pairing start response";
  const object = expectExactObject(value, ["pairingExpiresAt", "serverTime", "userCode"], context);
  return {
    pairingExpiresAt: parseTimestamp(readProperty(object, "pairingExpiresAt", context), `${context}.pairingExpiresAt`),
    serverTime: parseTimestamp(readProperty(object, "serverTime", context), `${context}.serverTime`),
    userCode: parseUserCode(readProperty(object, "userCode", context), `${context}.userCode`)
  };
}

export function parsePairingApproveResponse(value: unknown): PairingApproveResponse {
  const object = expectExactObject(value, ["state"], "pairing approve response");
  if (readProperty(object, "state", "pairing approve response") !== "approved") {
    throw new ContractValidationError("pairing approve response.state is invalid");
  }
  return { state: "approved" };
}

export function parsePairingRedeemResponse(value: unknown): PairingRedeemResponse {
  const context = "pairing redeem response";
  if (typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).length === 2) {
    const object = expectExactObject(value, ["pairingExpiresAt", "state"], context);
    if (readProperty(object, "state", context) !== "pending") {
      throw new ContractValidationError(`${context}.state is invalid`);
    }
    return {
      pairingExpiresAt: parseTimestamp(readProperty(object, "pairingExpiresAt", context), `${context}.pairingExpiresAt`),
      state: "pending"
    };
  }
  const object = expectExactObject(value, ["permit", "permitExpiresAt", "serverTime", "state"], context);
  if (readProperty(object, "state", context) !== "approved") {
    throw new ContractValidationError(`${context}.state is invalid`);
  }
  return {
    permit: parsePermitValue(readProperty(object, "permit", context), `${context}.permit`),
    permitExpiresAt: parseTimestamp(readProperty(object, "permitExpiresAt", context), `${context}.permitExpiresAt`),
    serverTime: parseTimestamp(readProperty(object, "serverTime", context), `${context}.serverTime`),
    state: "approved"
  };
}

export function parseDevicePairingStartRequest(value: unknown): DevicePairingStartRequest {
  const context = "device pairing start request";
  const object = expectExactObject(value, ["deviceLocator", "deviceToken", "maxDays"], context);
  return {
    deviceLocator: parseLocator(readProperty(object, "deviceLocator", context), `${context}.deviceLocator`),
    deviceToken: parseToken(readProperty(object, "deviceToken", context), `${context}.deviceToken`),
    maxDays: parseDeviceGrantDays(readProperty(object, "maxDays", context), `${context}.maxDays`)
  };
}

export function parseDevicePairingStartRequestJson(text: string): DevicePairingStartRequest {
  return parseApiJsonText(text, parseDevicePairingStartRequest);
}

export function parseDevicePairingApproveRequestJson(text: string): DevicePairingApproveRequest {
  return parseApiJsonText(text, parsePairingApproveRequest);
}

export function parseDevicePairingClaimStatusResponse(value: unknown): DevicePairingClaimStatusResponse {
  const context = "device claim status response";
  const object = expectExactObject(value, ["maxDays", "pairingExpiresAt"], context);
  return {
    maxDays: parseDeviceGrantDays(readProperty(object, "maxDays", context), `${context}.maxDays`),
    pairingExpiresAt: parseTimestamp(readProperty(object, "pairingExpiresAt", context), `${context}.pairingExpiresAt`)
  };
}

export function parseDevicePairingClaimRequest(value: unknown): DevicePairingClaimRequest {
  const context = "device claim request";
  if (isObjectWithKeyCount(value, 1)) {
    const object = expectExactObject(value, ["scope"], context);
    if (readProperty(object, "scope", context) !== "transfer") {
      throw new ContractValidationError(`${context}.scope is invalid`);
    }
    return { scope: "transfer" };
  }
  const object = expectExactObject(value, ["days", "manageToken", "scope"], context);
  if (readProperty(object, "scope", context) !== "device") {
    throw new ContractValidationError(`${context}.scope is invalid`);
  }
  return {
    days: parseDeviceGrantDays(readProperty(object, "days", context), `${context}.days`),
    manageToken: parseToken(readProperty(object, "manageToken", context), `${context}.manageToken`),
    scope: "device"
  };
}

export function parseDevicePairingClaimRequestJson(text: string): DevicePairingClaimRequest {
  return parseApiJsonText(text, parseDevicePairingClaimRequest);
}

export function parseDevicePairingClaimResponse(value: unknown): DevicePairingClaimResponse {
  const context = "device claim response";
  if (isObjectWithKeyCount(value, 1)) {
    const object = expectExactObject(value, ["scope"], context);
    if (readProperty(object, "scope", context) !== "transfer") {
      throw new ContractValidationError(`${context}.scope is invalid`);
    }
    return { scope: "transfer" };
  }
  const object = expectExactObject(value, ["deviceExpiresAt", "deviceLocator", "scope"], context);
  if (readProperty(object, "scope", context) !== "device") {
    throw new ContractValidationError(`${context}.scope is invalid`);
  }
  return {
    deviceExpiresAt: parseTimestamp(readProperty(object, "deviceExpiresAt", context), `${context}.deviceExpiresAt`),
    deviceLocator: parseLocator(readProperty(object, "deviceLocator", context), `${context}.deviceLocator`),
    scope: "device"
  };
}

export function parseDevicePairingRedeemRequest(value: unknown): DevicePairingRedeemRequest {
  const context = "device pairing redeem request";
  const object = expectExactObject(value, ["deviceToken", "userCode"], context);
  return {
    deviceToken: parseToken(readProperty(object, "deviceToken", context), `${context}.deviceToken`),
    userCode: parseUserCode(readProperty(object, "userCode", context), `${context}.userCode`)
  };
}

export function parseDevicePairingRedeemRequestJson(text: string): DevicePairingRedeemRequest {
  return parseApiJsonText(text, parseDevicePairingRedeemRequest);
}

export function parseDevicePairingRedeemResponse(value: unknown): DevicePairingRedeemResponse {
  const context = "device pairing redeem response";
  if (isObjectWithKeyCount(value, 2) && hasKey(value, "pairingExpiresAt")) {
    const object = expectExactObject(value, ["pairingExpiresAt", "state"], context);
    if (readProperty(object, "state", context) !== "pending") {
      throw new ContractValidationError(`${context}.state is invalid`);
    }
    return {
      pairingExpiresAt: parseTimestamp(readProperty(object, "pairingExpiresAt", context), `${context}.pairingExpiresAt`),
      state: "pending"
    };
  }
  if (isObjectWithKeyCount(value, 2)) {
    const object = expectExactObject(value, ["deviceExpiresAt", "state"], context);
    if (readProperty(object, "state", context) !== "device") {
      throw new ContractValidationError(`${context}.state is invalid`);
    }
    return {
      deviceExpiresAt: parseTimestamp(readProperty(object, "deviceExpiresAt", context), `${context}.deviceExpiresAt`),
      state: "device"
    };
  }
  const object = expectExactObject(value, ["permit", "permitExpiresAt", "serverTime", "state"], context);
  if (readProperty(object, "state", context) !== "transfer") {
    throw new ContractValidationError(`${context}.state is invalid`);
  }
  return {
    permit: parsePermitValue(readProperty(object, "permit", context), `${context}.permit`),
    permitExpiresAt: parseTimestamp(readProperty(object, "permitExpiresAt", context), `${context}.permitExpiresAt`),
    serverTime: parseTimestamp(readProperty(object, "serverTime", context), `${context}.serverTime`),
    state: "transfer"
  };
}

export function parseDevicePermitRequest(value: unknown): DevicePermitRequest {
  const context = "device permit request";
  const object = expectExactObject(value, ["deviceLocator", "deviceToken", "requestId"], context);
  return {
    deviceLocator: parseLocator(readProperty(object, "deviceLocator", context), `${context}.deviceLocator`),
    deviceToken: parseToken(readProperty(object, "deviceToken", context), `${context}.deviceToken`),
    requestId: parseRequestId(readProperty(object, "requestId", context))
  };
}

export function parseDevicePermitRequestJson(text: string): DevicePermitRequest {
  return parseApiJsonText(text, parseDevicePermitRequest);
}

export function parseDevicePermitResponse(value: unknown): DevicePermitResponse {
  const context = "device permit response";
  const object = expectExactObject(value, ["permit", "permitExpiresAt", "serverTime"], context);
  return {
    permit: parsePermitValue(readProperty(object, "permit", context), `${context}.permit`, "v3."),
    permitExpiresAt: parseTimestamp(readProperty(object, "permitExpiresAt", context), `${context}.permitExpiresAt`),
    serverTime: parseTimestamp(readProperty(object, "serverTime", context), `${context}.serverTime`)
  };
}

export function parseDeviceAccessRequest(value: unknown): DeviceAccessRequest {
  const context = "device access request";
  if (hasKey(value, "manageToken")) {
    const object = expectExactObject(value, ["deviceLocator", "manageToken"], context);
    return {
      deviceLocator: parseLocator(readProperty(object, "deviceLocator", context), `${context}.deviceLocator`),
      manageToken: parseToken(readProperty(object, "manageToken", context), `${context}.manageToken`)
    };
  }
  const object = expectExactObject(value, ["deviceLocator", "deviceToken"], context);
  return {
    deviceLocator: parseLocator(readProperty(object, "deviceLocator", context), `${context}.deviceLocator`),
    deviceToken: parseToken(readProperty(object, "deviceToken", context), `${context}.deviceToken`)
  };
}

export function parseDeviceAccessRequestJson(text: string): DeviceAccessRequest {
  return parseApiJsonText(text, parseDeviceAccessRequest);
}

export function parseDeviceStatusResponse(value: unknown): DeviceStatusResponse {
  const context = "device status response";
  const object = expectExactObject(value, ["expiresAt", "hourlyMints", "quotaRemaining", "state"], context);
  const state = readProperty(object, "state", context);
  if (state !== "active" && state !== "revoked") {
    throw new ContractValidationError(`${context}.state is invalid`);
  }
  return {
    expiresAt: parseTimestamp(readProperty(object, "expiresAt", context), `${context}.expiresAt`),
    hourlyMints: expectArray(readProperty(object, "hourlyMints", context), DEVICE_QUOTA_WINDOW_HOURS, DEVICE_QUOTA_WINDOW_HOURS, `${context}.hourlyMints`)
      .map((entry, index) => expectIntegerInRange(entry, 0, DEVICE_QUOTA_PER_DAY, `${context}.hourlyMints[${index}]`)),
    quotaRemaining: expectIntegerInRange(readProperty(object, "quotaRemaining", context), 0, DEVICE_QUOTA_PER_DAY, `${context}.quotaRemaining`),
    state
  };
}

export function parseEmptyRequest(value: unknown): Record<string, never> {
  return parseEmpty(value);
}

export function parseEmptyRequestJson(text: string): Record<string, never> {
  return parseApiJsonText(text, parseEmpty);
}

export function parseSendCreateRequest(value: unknown): SendCreateRequest {
  const context = "send create request";
  const object = expectExactObject(
    value,
    [
      "attemptId",
      "clientNotAfter",
      "envelope",
      "locator",
      "manageToken",
      "maxRetrievals",
      "retrieveToken",
      "settleNotAfter",
      "ttlSeconds"
    ],
    context
  );
  const envelope = parseKxe1Envelope(readProperty(object, "envelope", context));
  const clientNotAfter = parseTimestamp(readProperty(object, "clientNotAfter", context), `${context}.clientNotAfter`);
  const maxRetrievals = expectIntegerInRange(readProperty(object, "maxRetrievals", context), 1, 10, `${context}.maxRetrievals`);
  if (envelope.contentMode !== 1 || envelope.clientNotAfter !== clientNotAfter || envelope.maxRetrievals !== maxRetrievals) {
    throw new ContractValidationError("send create request does not match its KXE1 header");
  }
  return {
    attemptId: parseAttempt(readProperty(object, "attemptId", context), `${context}.attemptId`),
    clientNotAfter,
    envelope: envelope.encoded,
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    manageToken: parseToken(readProperty(object, "manageToken", context), `${context}.manageToken`),
    maxRetrievals,
    retrieveToken: parseToken(readProperty(object, "retrieveToken", context), `${context}.retrieveToken`),
    settleNotAfter: parseTimestamp(readProperty(object, "settleNotAfter", context), `${context}.settleNotAfter`),
    ttlSeconds: parseTtl(readProperty(object, "ttlSeconds", context), `${context}.ttlSeconds`)
  };
}

export function parseSendCreateRequestJson(text: string): SendCreateRequest {
  return parseApiJsonText(text, parseSendCreateRequest);
}

export function parseRequestCreateRequest(value: unknown): RequestCreateRequest {
  const context = "request create request";
  const object = expectExactObject(
    value,
    ["attemptId", "clientNotAfter", "envelope", "locator", "ownerToken", "settleNotAfter", "ttlSeconds", "writeToken"],
    context
  );
  const envelope = parseKxe1Envelope(readProperty(object, "envelope", context));
  const clientNotAfter = parseTimestamp(readProperty(object, "clientNotAfter", context), `${context}.clientNotAfter`);
  if (envelope.contentMode !== 2 || envelope.clientNotAfter !== clientNotAfter || envelope.maxRetrievals !== 0) {
    throw new ContractValidationError("request create request does not match its KXE1 header");
  }
  return {
    attemptId: parseAttempt(readProperty(object, "attemptId", context), `${context}.attemptId`),
    clientNotAfter,
    envelope: envelope.encoded,
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    ownerToken: parseToken(readProperty(object, "ownerToken", context), `${context}.ownerToken`),
    settleNotAfter: parseTimestamp(readProperty(object, "settleNotAfter", context), `${context}.settleNotAfter`),
    ttlSeconds: parseTtl(readProperty(object, "ttlSeconds", context), `${context}.ttlSeconds`),
    writeToken: parseToken(readProperty(object, "writeToken", context), `${context}.writeToken`)
  };
}

export function parseRequestCreateRequestJson(text: string): RequestCreateRequest {
  return parseApiJsonText(text, parseRequestCreateRequest);
}

export function parseSendRetrieveRequest(value: unknown): SendRetrieveRequest {
  const context = "send retrieve request";
  const object = expectExactObject(value, ["locator", "retrieveToken"], context);
  return {
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    retrieveToken: parseToken(readProperty(object, "retrieveToken", context), `${context}.retrieveToken`)
  };
}

export function parseSendRetrieveRequestJson(text: string): SendRetrieveRequest {
  return parseApiJsonText(text, parseSendRetrieveRequest);
}

export function parseSendManageRequest(value: unknown): SendManageRequest {
  const context = "send management request";
  const object = expectExactObject(value, ["locator", "manageToken"], context);
  return {
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    manageToken: parseToken(readProperty(object, "manageToken", context), `${context}.manageToken`)
  };
}

export function parseSendManageRequestJson(text: string): SendManageRequest {
  return parseApiJsonText(text, parseSendManageRequest);
}

export function parseSendShortenRequest(value: unknown): SendShortenRequest {
  const context = "send shorten request";
  const object = expectExactObject(value, ["locator", "manageToken", "serverExpiresAt"], context);
  return {
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    manageToken: parseToken(readProperty(object, "manageToken", context), `${context}.manageToken`),
    serverExpiresAt: parseTimestamp(readProperty(object, "serverExpiresAt", context), `${context}.serverExpiresAt`)
  };
}

export function parseSendShortenRequestJson(text: string): SendShortenRequest {
  return parseApiJsonText(text, parseSendShortenRequest);
}

export function parseRequestWriteRequest(value: unknown): RequestWriteRequest {
  const context = "request write request";
  const object = expectExactObject(value, ["locator", "writeToken"], context);
  return {
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    writeToken: parseToken(readProperty(object, "writeToken", context), `${context}.writeToken`)
  };
}

export function parseRequestWriteRequestJson(text: string): RequestWriteRequest {
  return parseApiJsonText(text, parseRequestWriteRequest);
}

export function parseRequestSubmitRequest(value: unknown): RequestSubmitRequest {
  const context = "request submit request";
  const object = expectExactObject(value, ["envelope", "locator", "writeToken"], context);
  const envelope = parseKxr1Envelope(readProperty(object, "envelope", context));
  return {
    envelope: envelope.encoded,
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    writeToken: parseToken(readProperty(object, "writeToken", context), `${context}.writeToken`)
  };
}

export function parseRequestSubmitRequestJson(text: string): RequestSubmitRequest {
  return parseApiJsonText(text, parseRequestSubmitRequest);
}

export function parseRequestOwnerRequest(value: unknown): RequestOwnerRequest {
  const context = "request owner request";
  const object = expectExactObject(value, ["locator", "ownerToken"], context);
  return {
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    ownerToken: parseToken(readProperty(object, "ownerToken", context), `${context}.ownerToken`)
  };
}

export function parseRequestOwnerRequestJson(text: string): RequestOwnerRequest {
  return parseApiJsonText(text, parseRequestOwnerRequest);
}

export function parseRequestShortenRequest(value: unknown): RequestShortenRequest {
  const context = "request shorten request";
  const object = expectExactObject(value, ["locator", "ownerToken", "serverExpiresAt"], context);
  return {
    locator: parseLocator(readProperty(object, "locator", context), `${context}.locator`),
    ownerToken: parseToken(readProperty(object, "ownerToken", context), `${context}.ownerToken`),
    serverExpiresAt: parseTimestamp(readProperty(object, "serverExpiresAt", context), `${context}.serverExpiresAt`)
  };
}

export function parseRequestShortenRequestJson(text: string): RequestShortenRequest {
  return parseApiJsonText(text, parseRequestShortenRequest);
}

export function parseCreatePermitResponse(value: unknown): CreatePermitResponse {
  const context = "create permit response";
  const object = expectExactObject(value, ["permitExpiresAt", "serverTime"], context);
  return {
    permitExpiresAt: parseTimestamp(readProperty(object, "permitExpiresAt", context), `${context}.permitExpiresAt`),
    serverTime: parseTimestamp(readProperty(object, "serverTime", context), `${context}.serverTime`)
  };
}

export function parseCreatePermitStatusResponse(value: unknown): CreatePermitStatusResponse {
  const context = "create permit status response";
  const object = expectExactObject(value, ["permitExpiresAt", "serverTime", "state"], context);
  if (readProperty(object, "state", context) !== "unused") {
    throw new ContractValidationError(`${context}.state is invalid`);
  }
  return {
    permitExpiresAt: parseTimestamp(readProperty(object, "permitExpiresAt", context), `${context}.permitExpiresAt`),
    serverTime: parseTimestamp(readProperty(object, "serverTime", context), `${context}.serverTime`),
    state: "unused"
  };
}

export function parseCreateResourceResponse(value: unknown): CreateResourceResponse {
  const context = "create resource response";
  const object = expectExactObject(value, ["serverExpiresAt"], context);
  return { serverExpiresAt: parseTimestamp(readProperty(object, "serverExpiresAt", context), `${context}.serverExpiresAt`) };
}

export function parseSendStatusResponse(value: unknown): SendStatusResponse {
  const context = "send status response";
  const object = expectExactObject(
    value,
    ["failedAccessAttempts", "releasedAt", "remainingRetrievals", "serverExpiresAt", "state"],
    context
  );
  return {
    failedAccessAttempts: expectIntegerInRange(readProperty(object, "failedAccessAttempts", context), 0, FAILED_ACCESS_SATURATION, `${context}.failedAccessAttempts`),
    releasedAt: expectArray(readProperty(object, "releasedAt", context), 0, 10, `${context}.releasedAt`)
      .map((entry, index) => parseTimestamp(entry, `${context}.releasedAt[${index}]`)),
    remainingRetrievals: expectIntegerInRange(readProperty(object, "remainingRetrievals", context), 0, 10, `${context}.remainingRetrievals`),
    serverExpiresAt: parseTimestamp(readProperty(object, "serverExpiresAt", context), `${context}.serverExpiresAt`),
    state: parseSendState(readProperty(object, "state", context), `${context}.state`)
  };
}

export function parseRequestStatusResponse(value: unknown): RequestStatusResponse {
  const context = "request status response";
  const object = expectExactObject(value, ["serverExpiresAt", "state"], context);
  return {
    serverExpiresAt: parseTimestamp(readProperty(object, "serverExpiresAt", context), `${context}.serverExpiresAt`),
    state: parseRequestState(readProperty(object, "state", context), `${context}.state`)
  };
}

export function parseRequestSubmitResponse(value: unknown): RequestSubmitResponse {
  const context = "request submit response";
  const object = expectExactObject(value, ["receipt"], context);
  return { receipt: parseToken(readProperty(object, "receipt", context), `${context}.receipt`) };
}

export function parseRevokeResponse(value: unknown): RevokeResponse {
  const object = expectExactObject(value, ["state"], "revoke response");
  if (readProperty(object, "state", "revoke response") !== "revoked") {
    throw new ContractValidationError("revoke response.state is invalid");
  }
  return { state: "revoked" };
}

export function parseShortenResponse(value: unknown): ShortenResponse {
  const context = "shorten response";
  const object = expectExactObject(value, ["serverExpiresAt"], context);
  return { serverExpiresAt: parseTimestamp(readProperty(object, "serverExpiresAt", context), `${context}.serverExpiresAt`) };
}

export function parseApiErrorResponse(value: unknown): ApiErrorResponse {
  const object = expectExactObject(value, ["error"], "API error response");
  return { error: parseErrorCode(readProperty(object, "error", "API error response")) };
}

function parseHeaderInteger(headers: Headers, name: string, minimum: number, maximum: number): number {
  const raw = headers.get(name);
  if (raw === null || !/^(?:0|[1-9][0-9]*)$/.test(raw)) {
    throw new ContractValidationError(`${name} is missing or invalid`);
  }
  const value = Number(raw);
  return expectIntegerInRange(value, minimum, maximum, name);
}

export function parseSendRetrieveMetadata(headers: Headers): SendRetrieveMetadata {
  return {
    remainingReleases: parseHeaderInteger(headers, "Kryptex-Remaining-Releases", 0, 9),
    serverExpiresAt: parseHeaderInteger(headers, "Kryptex-Server-Expires-At", 0, Number.MAX_SAFE_INTEGER)
  };
}

export function parseRequestSchemaMetadata(headers: Headers): RequestSchemaMetadata {
  return {
    serverExpiresAt: parseHeaderInteger(headers, "Kryptex-Server-Expires-At", 0, Number.MAX_SAFE_INTEGER)
  };
}

export function parseRequestPickupMetadata(headers: Headers): RequestPickupMetadata {
  return {
    receipt: parseToken(headers.get("Kryptex-Receipt"), "Kryptex-Receipt"),
    serverExpiresAt: parseHeaderInteger(headers, "Kryptex-Server-Expires-At", 0, Number.MAX_SAFE_INTEGER)
  };
}

export function parseServerTimeMetadata(headers: Headers): ServerTimeMetadata {
  return {
    serverTime: parseHeaderInteger(headers, "Kryptex-Server-Time", 0, Number.MAX_SAFE_INTEGER)
  };
}

export function parseStateCheckedMetadata(headers: Headers): StateCheckedMetadata {
  return {
    stateCheckedAt: parseHeaderInteger(headers, "Kryptex-State-Checked-At", 0, Number.MAX_SAFE_INTEGER)
  };
}
