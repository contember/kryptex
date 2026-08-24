import type { RequestState, SendState } from "@kryptex/contracts/api";
import type { RequestFieldType, ValueFieldType } from "@kryptex/contracts/payloads";
import { FAILED_ACCESS_SATURATION, type TtlSeconds } from "@kryptex/contracts/protocol";

export type StateTone = "quiet" | "success" | "warning" | "danger";

const FIELD_TYPE_LABELS: Readonly<Record<RequestFieldType, string>> = {
  "instruction": "Instruction — label only",
  "long-secret": "Long secret — multi-line",
  "long-text": "Long text — multi-line",
  "secret": "Secret",
  "text": "Plain text"
};

export const VALUE_FIELD_TYPES: readonly ValueFieldType[] = ["secret", "text", "long-secret", "long-text"];

export function formatFieldType(type: RequestFieldType): string {
  return FIELD_TYPE_LABELS[type];
}

export function isValueFieldType(value: string): value is ValueFieldType {
  return value === "secret" || value === "text" || value === "long-secret" || value === "long-text";
}

/** Sensitive values are entered masked where the control allows it and are shown in monospace. */
export function isSensitiveField(type: RequestFieldType): boolean {
  return type === "secret" || type === "long-secret";
}

export function isMultilineField(type: RequestFieldType): boolean {
  return type === "long-secret" || type === "long-text";
}

export interface StateDescription {
  readonly detail: string;
  readonly label: string;
  readonly tone: StateTone;
}

const TTL_LABELS: Readonly<Record<TtlSeconds, string>> = {
  900: "15 minutes",
  3600: "1 hour",
  28800: "8 hours",
  86400: "1 day",
  259200: "3 days",
  604800: "7 days",
  1209600: "14 days",
  2592000: "30 days"
};

export const TTL_CHOICES: readonly TtlSeconds[] = [900, 3600, 28800, 86400, 259200, 604800, 1209600, 2592000];
export const DEFAULT_TTL: TtlSeconds = 604800;

export function formatTtl(ttl: TtlSeconds): string {
  return TTL_LABELS[ttl];
}

function plural(count: number, unit: string): string {
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}

/** Coarse and always rounded down, so the wording never promises more time than is left. */
export function formatTimeLeft(expiresAt: number, nowSeconds: number): string {
  const remaining = expiresAt - nowSeconds;
  if (remaining <= 0) return "already passed";
  if (remaining < 60) return "in under a minute";
  if (remaining < 3_600) return `in ${plural(Math.floor(remaining / 60), "minute")}`;
  if (remaining < 86_400) return `in ${plural(Math.floor(remaining / 3_600), "hour")}`;
  return `in ${plural(Math.floor(remaining / 86_400), "day")}`;
}

export function formatExactTime(expiresAt: number): string {
  return new Date(expiresAt * 1_000).toLocaleString();
}

export function formatOpens(count: number): string {
  if (count <= 0) return "no opens left";
  if (count === 1) return "1 open left";
  return `${count} opens left`;
}

export function formatOpened(count: number): string {
  if (count === 0) return "Not opened yet";
  if (count === 1) return "Opened once";
  if (count === 2) return "Opened twice";
  return `Opened ${count} times`;
}

/** The stored counter saturates, so the top of the range reads as a floor rather than an exact count. */
export function formatFailedAttempts(count: number): string {
  return count >= FAILED_ACCESS_SATURATION ? `${FAILED_ACCESS_SATURATION}+` : String(count);
}

export function formatOpenAllowance(maximum: number): string {
  if (maximum === 1) return "can be opened once";
  if (maximum === 2) return "can be opened twice";
  return `can be opened ${maximum} times`;
}

export function describeSendState(state: SendState): StateDescription {
  if (state === "active") {
    return { detail: "The recipient can still open this secret.", label: "Active", tone: "success" };
  }
  if (state === "exhausted") {
    return { detail: "Every allowed open has been used. Nothing can be released again.", label: "All opens used", tone: "warning" };
  }
  if (state === "revoked") {
    return { detail: "This secret was revoked and can no longer be opened.", label: "Revoked", tone: "danger" };
  }
  return { detail: "The expiry time passed. Nothing can be released, and stored-ciphertext deletion may still be retrying.", label: "Expired", tone: "warning" };
}

export function describeRequestState(state: RequestState): StateDescription {
  if (state === "waiting") {
    return { detail: "Nobody has answered yet. Check back after you share the write link.", label: "Waiting for an answer", tone: "quiet" };
  }
  if (state === "submitted") {
    return { detail: "An answer is waiting for you. Opening it releases it once.", label: "Answer ready", tone: "success" };
  }
  if (state === "picked_up") {
    return { detail: "The answer was already released. It cannot be released again.", label: "Answer opened", tone: "warning" };
  }
  if (state === "revoked") {
    return { detail: "This request was revoked and can no longer be answered.", label: "Revoked", tone: "danger" };
  }
  return { detail: "The expiry time passed. Nothing can be released, and stored-ciphertext deletion may still be retrying.", label: "Expired", tone: "warning" };
}
