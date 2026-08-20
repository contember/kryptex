import type { ApiErrorCode } from "@kryptex/contracts/api";
import { unixSeconds } from "./core.js";

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

export function jsonResponse(value: object, status = 200, headers?: HeadersInit): Response {
  const outputHeaders = new Headers(headers);
  outputHeaders.set("Content-Type", JSON_CONTENT_TYPE);
  return new Response(JSON.stringify(value), { headers: outputHeaders, status });
}

export function apiError(error: ApiErrorCode, status: number, headers?: HeadersInit): Response {
  return jsonResponse({ error }, status, headers);
}

export function unavailable(headers?: HeadersInit): Response {
  return apiError("unavailable", 404, headers);
}

export function rateLimited(): Response {
  return apiError("rate_limited", 429);
}

export function binaryResponse(bytes: Uint8Array, headers: HeadersInit): Response {
  const outputHeaders = new Headers(headers);
  outputHeaders.set("Content-Type", "application/octet-stream");
  return new Response(Uint8Array.from(bytes).buffer, { headers: outputHeaders, status: 200 });
}

export function finalizeApiResponse(response: Response, origin: string, setCookie?: string): Response {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Kryptex-Server-Time", String(unixSeconds()));
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");
  if (setCookie !== undefined) {
    headers.append("Set-Cookie", setCookie);
  }
  return new Response(response.body, { headers, status: response.status, statusText: response.statusText });
}

export function expiredPermitCookie(): string {
  return "kx_create=; Max-Age=0; Path=/api/v1/; Secure; HttpOnly; SameSite=Strict";
}

export function permitCookie(seed: string): string {
  return `kx_create=v1.${seed}; Max-Age=300; Path=/api/v1/; Secure; HttpOnly; SameSite=Strict`;
}

const APPLICATION_CSP = [
  "base-uri 'none'",
  "connect-src 'self'",
  "default-src 'none'",
  "font-src 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "img-src 'self' data:",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "script-src 'self'",
  "style-src 'self'",
  "trusted-types kryptex",
  "worker-src 'none'"
].join("; ");

const GATE_CSP = [
  "base-uri 'none'",
  "connect-src 'self' https://challenges.cloudflare.com",
  "default-src 'none'",
  "font-src 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "frame-src https://challenges.cloudflare.com",
  "img-src 'self' data: https://challenges.cloudflare.com",
  "object-src 'none'",
  "script-src 'self' https://challenges.cloudflare.com",
  "style-src 'self'",
  "worker-src 'none'"
].join("; ");

export function secureAssetResponse(response: Response, gate: boolean): Response {
  const headers = new Headers(response.headers);
  headers.set("Content-Security-Policy", gate ? GATE_CSP : APPLICATION_CSP);
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=(), clipboard-read=(self), clipboard-write=(self)");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText
  });
}

export function normalizeBindingResponse(response: Response): Response {
  return response.status >= 500 ? apiError("internal_error", 500) : response;
}
