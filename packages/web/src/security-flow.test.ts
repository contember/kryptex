import { describe, expect, it } from "vitest";
import { encodeBundle, randomBytes } from "@kryptex/crypto";
import { consumeBundle } from "./crypto-flow";
import type { FragmentCapture } from "./fragment";
import { resolveTurnstileSiteKey } from "./pages/static-pages";

describe("secret route boot", () => {
  it("survives a StrictMode-style second read while wiping captured bytes", () => {
    const encoded = encodeBundle({ factorMode: 0, kind: 1, salt: new Uint8Array(16), sendSeed: randomBytes(32), serverExpiresAt: 1_800_000_000 });
    const bytes = new TextEncoder().encode(encoded);
    const capture: FragmentCapture = { canonicalPathname: "/s", fragmentBytes: bytes, hadFragment: true };
    expect(consumeBundle(capture, 1)?.kind).toBe(1);
    expect(bytes.every((byte) => byte === 0)).toBe(true);
    expect(consumeBundle(capture, 1)?.kind).toBe(1);
  });
});

describe("Turnstile configuration", () => {
  it("fails closed without a production site key", () => {
    expect(resolveTurnstileSiteKey(undefined, true)).toBeNull();
    expect(resolveTurnstileSiteKey("", true)).toBeNull();
    expect(resolveTurnstileSiteKey(undefined, false)).toBe("1x00000000000000000000AA");
  });
});
