import { describe, expect, test } from "vitest";
import { normalizeBindingResponse, secureAssetResponse } from "./http.js";

describe("binding response normalization", () => {
  test("replaces every binding 5xx body with the fixed internal error", async () => {
    for (const status of [500, 502, 503, 599]) {
      const response = normalizeBindingResponse(new Response(`platform detail ${status}`, {
        headers: { "Content-Type": "text/plain", "X-Upstream": "leak" },
        status
      }));
      expect(response.status).toBe(500);
      expect(response.headers.get("X-Upstream")).toBeNull();
      expect(await response.json()).toEqual({ error: "internal_error" });
    }
  });
});

describe("asset security policies", () => {
  test("preserves the asset response while adding the crypto-page policy", async () => {
    const source = new Response("asset", {
      headers: { "Cache-Control": "public, max-age=60", "Content-Type": "text/plain", ETag: "test-tag" },
      status: 206,
      statusText: "Partial Content"
    });
    const response = secureAssetResponse(source, false);
    expect(response.status).toBe(206);
    expect(response.statusText).toBe("Partial Content");
    expect(await response.text()).toBe("asset");
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=60");
    expect(response.headers.get("Content-Type")).toBe("text/plain");
    expect(response.headers.get("ETag")).toBe("test-tag");
    expect(response.headers.get("Content-Security-Policy")).toContain("require-trusted-types-for 'script'");
    expect(response.headers.get("Content-Security-Policy")).not.toContain("challenges.cloudflare.com");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
  });

  test("scopes Turnstile origins to the gate policy", () => {
    const response = secureAssetResponse(new Response("gate"), true);
    const policy = response.headers.get("Content-Security-Policy");
    expect(policy).toContain("script-src 'self' https://challenges.cloudflare.com");
    expect(policy).toContain("frame-src https://challenges.cloudflare.com");
    expect(policy).not.toContain("require-trusted-types-for 'script'");
  });
});
