import {
  parseApiErrorResponse,
  parseApiJsonText,
  parseCreatePermitResponse,
  parseCreatePermitStatusResponse,
  parseCreateResourceResponse,
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
import { API_ROUTES } from "@kryptex/contracts/protocol";

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

export class KryptexClient {
  readonly #fetch: typeof fetch;
  readonly #origin: string;

  constructor(fetchImplementation: typeof fetch = (input, init) => fetch(input, init), origin: string = typeof window === "undefined" ? "http://localhost" : window.location.origin) {
    this.#fetch = fetchImplementation;
    this.#origin = new URL(origin).origin;
  }

  async #post(route: string, body: object, ambiguousAfterDispatch: boolean): Promise<Response> {
    const url = new URL(route, this.#origin);
    if (url.origin !== this.#origin || url.pathname !== route || url.search !== "" || url.hash !== "") {
      throw new ApiFailure("invalid_response", false);
    }
    try {
      return await this.#fetch(url, {
        body: JSON.stringify(body),
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        method: "POST"
      });
    } catch {
      throw new ApiFailure("network", ambiguousAfterDispatch);
    }
  }

  async #json<T>(route: string, body: object, parser: JsonParser<T>, ambiguousAfterDispatch: boolean): Promise<T> {
    const response = await this.#post(route, body, ambiguousAfterDispatch);
    try { parseServerTimeMetadata(response.headers); } catch { throw new ApiFailure("invalid_response", ambiguousAfterDispatch); }
    let text: string;
    try { text = await response.text(); } catch { throw new ApiFailure("invalid_response", ambiguousAfterDispatch); }
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
        throw new ApiFailure(code, response.status >= 500 ? ambiguousAfterDispatch : code === "gate_unavailable" && route === API_ROUTES.createPermit, stateCheckedAt);
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
      try { text = await response.text(); } catch { throw new ApiFailure("invalid_response", ambiguousAfterDispatch); }
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
      return { bytes: new Uint8Array(await response.arrayBuffer()), metadata: metadata(response.headers) };
    } catch {
      throw new ApiFailure("invalid_response", ambiguousAfterDispatch);
    }
  }

  createPermit(input: CreatePermitRequest): Promise<CreatePermitResponse> {
    return this.#json(API_ROUTES.createPermit, input, parseCreatePermitResponse, true);
  }
  permitStatus(): Promise<CreatePermitStatusResponse> {
    return this.#json(API_ROUTES.createPermitStatus, {}, parseCreatePermitStatusResponse, false);
  }
  createSend(input: SendCreateRequest): Promise<CreateResourceResponse> {
    return this.#json(API_ROUTES.sendCreate, input, parseCreateResourceResponse, true);
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
  createRequest(input: RequestCreateRequest): Promise<CreateResourceResponse> {
    return this.#json(API_ROUTES.requestCreate, input, parseCreateResourceResponse, true);
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
      text = await response.text();
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

export const browserClient = new KryptexClient();
