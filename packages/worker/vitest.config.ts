import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" }
    })
  ],
  root: import.meta.dirname,
  test: {
    include: ["src/**/*.test.ts"],
    name: "worker"
  }
});
