import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        bindings: {
          CAPABILITY_HMAC_KEYRING: '{"dev-v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}',
          PERMIT_ISSUANCE_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          RATE_LIMIT_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          TURNSTILE_SECRET_KEY: "test-turnstile-secret"
        },
        ratelimits: {
          EDGE_RATE_LIMITER: {
            namespace_id: "1454624106",
            simple: {
              limit: 120,
              period: 60
            }
          },
          LOCATOR_RATE_LIMITER: {
            namespace_id: "1454624107",
            simple: {
              limit: 30,
              period: 60
            }
          }
        }
      },
      wrangler: { configPath: "./wrangler.jsonc" }
    })
  ],
  root: import.meta.dirname,
  test: {
    include: ["src/**/*.test.ts"],
    name: "worker"
  }
});
