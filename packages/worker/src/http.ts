import type { ApiErrorCode } from "@kryptex/contracts/api";
import { CREATE_PERMIT_V2_TTL_SECONDS, unixSeconds } from "./core.js";

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
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
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
  return "kx_create_v2=; Max-Age=0; Path=/api/; Secure; HttpOnly; SameSite=Strict";
}

export function permitCookie(seed: string): string {
  return `kx_create_v2=v2.${seed}; Max-Age=${CREATE_PERMIT_V2_TTL_SECONDS}; Path=/api/; Secure; HttpOnly; SameSite=Strict`;
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
  "script-src 'self' 'wasm-unsafe-eval'",
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
  headers.set(
    "Permissions-Policy",
    gate
      ? "camera=(), geolocation=(), microphone=(), payment=(), usb=(), clipboard-read=(), clipboard-write=()"
      : "camera=(), geolocation=(), microphone=(), payment=(), usb=(), clipboard-read=(), clipboard-write=(self)"
  );
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
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
