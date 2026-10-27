import {
  parseApiErrorResponse,
  parseApiJsonText,
  parseCreatePermitResponse,
  parseCreatePermitStatusResponse,
  parseCreateResourceResponse,
  parsePairingApproveResponse,
  parsePairingRedeemResponse,
  parsePairingStartResponse,
  parseRequestPickupMetadata,
  parseRequestSchemaMetadata,
  parseRequestStatusResponse,
  parseRequestSubmitResponse,
  parseRevokeResponse,
  parseSendRetrieveMetadata,
  parseSendStatusResponse,
  parseServerTimeMetadata,
  parseShortenResponse,
  parseStateCheckedMetadata,
  type ApiErrorCode,
  type CreatePermitRequest,
  type CreatePermitResponse,
  type CreatePermitStatusResponse,
  type CreateResourceResponse,
  type PairingApproveRequest,
  type PairingApproveResponse,
  type PairingRedeemRequest,
  type PairingRedeemResponse,
  type PairingStartRequest,
  type PairingStartResponse,
  type RequestCreateRequest,
  type RequestOwnerRequest,
  type RequestPickupMetadata,
  type RequestSchemaMetadata,
  type RequestShortenRequest,
  type RequestStatusResponse,
  type RequestSubmitRequest,
  type RequestSubmitResponse,
  type RequestWriteRequest,
  type RevokeResponse,
  type SendCreateRequest,
  type SendManageRequest,
  type SendRetrieveMetadata,
  type SendRetrieveRequest,
  type SendShortenRequest,
  type SendStatusResponse,
  type ShortenResponse,
  type StateCheckedMetadata
} from "@kryptex/contracts/api";
import { API_ROUTES, CREATE_PERMIT_HEADER, MAX_KXR1_LENGTH } from "@kryptex/contracts/protocol";

const MAX_JSON_RESPONSE_BYTES = 65_536;
const MAX_BINARY_RESPONSE_BYTES = MAX_KXR1_LENGTH + 1_024;
const NATIVE_REQUEST_TIMEOUT_MS = 30_000;

/**
 * A browser client sends the ambient permit cookie. A native client sends no cookie and no origin,
 * presents a permit only in its header, and bounds every request in time.
 */
export type ClientMode = "browser" | "native";

export class ApiFailure extends Error {
  readonly code: ApiErrorCode | "invalid_response" | "network";
  readonly ambiguous: boolean;
  readonly stateCheckedAt: number | null;

  constructor(code: ApiErrorCode | "invalid_response" | "network", ambiguous: boolean, stateCheckedAt: number | null = null) {
    super("Kryptex request failed");
    this.name = "ApiFailure";
    this.code = code;
    this.ambiguous = ambiguous;
    this.stateCheckedAt = stateCheckedAt;
  }
}

export interface BinaryResult<T> {
  readonly bytes: Uint8Array<ArrayBuffer>;
  readonly metadata: T;
}

type JsonParser<T> = (value: unknown) => T;

async function readBounded(response: Response, maximumBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  const declared = response.headers.get("Content-Length");
  if (declared !== null && Number(declared) > maximumBytes) {
    throw new Error("response too large");
  }
  if (response.body === null) {
    return new Uint8Array(0);
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
    length += chunk.value.byteLength;
    if (length > maximumBytes) {
      await reader.cancel();
      throw new Error("response too large");
    }
    chunks.push(chunk.value);
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function readBoundedText(response: Response): Promise<string> {
  return new TextDecoder("utf-8", { fatal: true }).decode(await readBounded(response, MAX_JSON_RESPONSE_BYTES));
}

export class KryptexClient {
  readonly #fetch: typeof fetch;
  readonly #origin: string;
  readonly #mode: ClientMode;

  constructor(
    fetchImplementation: typeof fetch = (input, init) => fetch(input, init),
    origin: string = typeof window === "undefined" ? "http://localhost" : window.location.origin,
    mode: ClientMode = "browser"
  ) {
    this.#fetch = fetchImplementation;
    this.#origin = new URL(origin).origin;
    this.#mode = mode;
  }

  async #post(route: string, body: object, ambiguousAfterDispatch: boolean, permit?: string): Promise<Response> {
    const url = new URL(route, this.#origin);
    if (url.origin !== this.#origin || url.pathname !== route || url.search !== "" || url.hash !== "") {
      throw new ApiFailure("invalid_response", false);
    }
    const headers = new Headers({ "Content-Type": "application/json" });
    if (permit !== undefined) {
      if (this.#mode !== "native") throw new ApiFailure("invalid_response", false);
      headers.set(CREATE_PERMIT_HEADER, permit);
    }
    try {
      return await this.#fetch(url, {
        body: JSON.stringify(body),
        credentials: this.#mode === "browser" ? "include" : "omit",
        headers,
        method: "POST",
        // A redirected POST would resend its body, and with it any capability, to another URL.
        redirect: "error",
        signal: this.#mode === "native" ? AbortSignal.timeout(NATIVE_REQUEST_TIMEOUT_MS) : null
      });
    } catch {
      throw new ApiFailure("network", ambiguousAfterDispatch);
    }
  }

  async #json<T>(route: string, body: object, parser: JsonParser<T>, ambiguousAfterDispatch: boolean, permit?: string): Promise<T> {
    const response = await this.#post(route, body, ambiguousAfterDispatch, permit);
    try { parseServerTimeMetadata(response.headers); } catch { throw new ApiFailure("invalid_response", ambiguousAfterDispatch); }
    let text: string;
    try { text = await readBoundedText(response); } catch { throw new ApiFailure("invalid_response", ambiguousAfterDispatch); }
    if (!response.ok) {
      let stateCheckedAt: number | null = null;
      if (response.status === 404 && response.headers.has("Kryptex-State-Checked-At")) {
        try {
          stateCheckedAt = parseStateCheckedMetadata(response.headers).stateCheckedAt;
        } catch {
          throw new ApiFailure("invalid_response", ambiguousAfterDispatch);
        }
      }
      try {
        const code = parseApiJsonText(text, parseApiErrorResponse).error;
        const gateRetry = code === "gate_unavailable" && (route === API_ROUTES.createPermit || route === API_ROUTES.pairingApprove);
        throw new ApiFailure(code, response.status >= 500 ? ambiguousAfterDispatch : gateRetry, stateCheckedAt);
      } catch (error) {
        if (error instanceof ApiFailure) throw error;
        throw new ApiFailure("invalid_response", ambiguousAfterDispatch, stateCheckedAt);
      }
    }
    try {
      return parseApiJsonText(text, parser);
    } catch {
      throw new ApiFailure("invalid_response", ambiguousAfterDispatch);
    }
  }

  async #binary<T>(route: string, body: object, metadata: (headers: Headers) => T, ambiguousAfterDispatch: boolean): Promise<BinaryResult<T>> {
    const response = await this.#post(route, body, ambiguousAfterDispatch);
    try { parseServerTimeMetadata(response.headers); } catch { throw new ApiFailure("invalid_response", ambiguousAfterDispatch); }
    if (!response.ok) {
      let text: string;
      try { text = await readBoundedText(response); } catch { throw new ApiFailure("invalid_response", ambiguousAfterDispatch); }
      try {
        const code = parseApiJsonText(text, parseApiErrorResponse).error;
        throw new ApiFailure(code, response.status >= 500 && ambiguousAfterDispatch);
      } catch (error) {
        if (error instanceof ApiFailure) throw error;
        throw new ApiFailure("invalid_response", ambiguousAfterDispatch);
      }
    }
    if (response.headers.get("Content-Type")?.split(";", 1)[0] !== "application/octet-stream") {
      throw new ApiFailure("invalid_response", ambiguousAfterDispatch);
    }
    try {
      return { bytes: await readBounded(response, MAX_BINARY_RESPONSE_BYTES), metadata: metadata(response.headers) };
    } catch {
      throw new ApiFailure("invalid_response", ambiguousAfterDispatch);
    }
  }

  createPermit(input: CreatePermitRequest): Promise<CreatePermitResponse> {
    return this.#json(API_ROUTES.createPermit, input, parseCreatePermitResponse, true);
  }
  /** `permit` is the native header value; a browser omits it and relies on its cookie. */
  permitStatus(permit?: string): Promise<CreatePermitStatusResponse> {
    return this.#json(API_ROUTES.createPermitStatus, {}, parseCreatePermitStatusResponse, false, permit);
  }
  startPairing(input: PairingStartRequest): Promise<PairingStartResponse> {
    return this.#json(API_ROUTES.pairingStart, input, parsePairingStartResponse, false);
  }
  approvePairing(input: PairingApproveRequest): Promise<PairingApproveResponse> {
    return this.#json(API_ROUTES.pairingApprove, input, parsePairingApproveResponse, true);
  }
  redeemPairing(input: PairingRedeemRequest): Promise<PairingRedeemResponse> {
    return this.#json(API_ROUTES.pairingRedeem, input, parsePairingRedeemResponse, false);
  }
  createSend(input: SendCreateRequest, permit?: string): Promise<CreateResourceResponse> {
    return this.#json(API_ROUTES.sendCreate, input, parseCreateResourceResponse, true, permit);
  }
  retrieveSend(input: SendRetrieveRequest): Promise<BinaryResult<SendRetrieveMetadata>> {
    return this.#binary(API_ROUTES.sendRetrieve, input, parseSendRetrieveMetadata, true);
  }
  sendStatus(input: SendManageRequest): Promise<SendStatusResponse & StateCheckedMetadata> {
    return this.#status(API_ROUTES.sendStatus, input, parseSendStatusResponse);
  }
  shortenSend(input: SendShortenRequest): Promise<ShortenResponse> {
    return this.#json(API_ROUTES.sendShorten, input, parseShortenResponse, true);
  }
  revokeSend(input: SendManageRequest): Promise<RevokeResponse> {
    return this.#json(API_ROUTES.sendRevoke, input, parseRevokeResponse, true);
  }
  createRequest(input: RequestCreateRequest, permit?: string): Promise<CreateResourceResponse> {
    return this.#json(API_ROUTES.requestCreate, input, parseCreateResourceResponse, true, permit);
  }
  requestSchema(input: RequestWriteRequest): Promise<BinaryResult<RequestSchemaMetadata>> {
    return this.#binary(API_ROUTES.requestSchema, input, parseRequestSchemaMetadata, false);
  }
  submitRequest(input: RequestSubmitRequest): Promise<RequestSubmitResponse> {
    return this.#json(API_ROUTES.requestSubmit, input, parseRequestSubmitResponse, true);
  }
  requestStatus(input: RequestOwnerRequest): Promise<RequestStatusResponse & StateCheckedMetadata> {
    return this.#status(API_ROUTES.requestStatus, input, parseRequestStatusResponse);
  }
  pickupRequest(input: RequestOwnerRequest): Promise<BinaryResult<RequestPickupMetadata>> {
    return this.#binary(API_ROUTES.requestPickup, input, parseRequestPickupMetadata, true);
  }
  shortenRequest(input: RequestShortenRequest): Promise<ShortenResponse> {
    return this.#json(API_ROUTES.requestShorten, input, parseShortenResponse, true);
  }
  revokeRequest(input: RequestOwnerRequest): Promise<RevokeResponse> {
    return this.#json(API_ROUTES.requestRevoke, input, parseRevokeResponse, true);
  }

  async #status<T>(route: string, body: object, parser: JsonParser<T>): Promise<T & StateCheckedMetadata> {
    const response = await this.#post(route, body, false);
    try {
      parseServerTimeMetadata(response.headers);
    } catch {
      throw new ApiFailure("invalid_response", false);
    }
    let checked: StateCheckedMetadata;
    try {
      checked = parseStateCheckedMetadata(response.headers);
    } catch {
      throw new ApiFailure("invalid_response", false);
    }
    let text: string;
    try {
      text = await readBoundedText(response);
    } catch {
      throw new ApiFailure("invalid_response", false, checked.stateCheckedAt);
    }
    if (!response.ok) {
      try {
        throw new ApiFailure(parseApiJsonText(text, parseApiErrorResponse).error, false, checked.stateCheckedAt);
      } catch (error) {
        if (error instanceof ApiFailure) throw error;
        throw new ApiFailure("invalid_response", false, checked.stateCheckedAt);
      }
    }
    try {
      return { ...parseApiJsonText(text, parser), ...checked };
    } catch {
      throw new ApiFailure("invalid_response", false);
    }
  }
}
