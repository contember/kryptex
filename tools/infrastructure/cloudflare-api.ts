const API_BASE_URL = "https://api.cloudflare.com/client/v4";

export class CloudflareApiError extends Error {
  public readonly status: number;

  public constructor(message: string, status: number) {
    super(message);
    this.name = "CloudflareApiError";
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

export interface CloudflareApi {
  readonly accountId: string;
  request(path: string, init?: RequestInit): Promise<unknown>;
}

export function cloudflareApiFromEnvironment(): CloudflareApi {
  const accountId = requiredEnvironment("CLOUDFLARE_ACCOUNT_ID");
  const apiToken = requiredEnvironment("CLOUDFLARE_API_TOKEN");

  return {
    accountId,
    async request(path, init) {
      const headers = new Headers(init?.headers);
      headers.set("Authorization", `Bearer ${apiToken}`);
      if (init?.body !== undefined) {
        headers.set("Content-Type", "application/json");
      }

      const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
      const text = await response.text();
      let payload: unknown;
      try {
        payload = JSON.parse(text);
      } catch {
        throw new CloudflareApiError("Cloudflare API returned invalid JSON", response.status);
      }
      if (!isRecord(payload) || payload["success"] !== true || !("result" in payload)) {
        throw new CloudflareApiError(`Cloudflare API request failed with HTTP ${response.status}`, response.status);
      }
      if (!response.ok) {
        throw new CloudflareApiError(`Cloudflare API request failed with HTTP ${response.status}`, response.status);
      }
      return payload["result"];
    }
  };
}
