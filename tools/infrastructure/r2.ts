import { CloudflareApiError, cloudflareApiFromEnvironment, type CloudflareApi } from "./cloudflare-api.js";
import {
  CIPHERTEXT_BUCKET_NAME,
  reconcileLifecycleRules,
  verifyLifecycleRules
} from "./r2-policy.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function bucketPath(api: CloudflareApi): string {
  return `/accounts/${encodeURIComponent(api.accountId)}/r2/buckets/${encodeURIComponent(CIPHERTEXT_BUCKET_NAME)}`;
}

async function ensureBucket(api: CloudflareApi): Promise<void> {
  try {
    await api.request(bucketPath(api));
    console.log(`R2 bucket exists: ${CIPHERTEXT_BUCKET_NAME}`);
  } catch (error) {
    if (!(error instanceof CloudflareApiError) || error.status !== 404) {
      throw error;
    }
    await api.request(`/accounts/${encodeURIComponent(api.accountId)}/r2/buckets`, {
      body: JSON.stringify({ name: CIPHERTEXT_BUCKET_NAME }),
      method: "POST"
    });
    console.log(`Created private R2 bucket: ${CIPHERTEXT_BUCKET_NAME}`);
  }
}

async function readLifecycleRules(api: CloudflareApi): Promise<readonly unknown[]> {
  const result = await api.request(`${bucketPath(api)}/lifecycle`);
  if (!isRecord(result) || !isUnknownArray(result["rules"])) {
    throw new Error("Cloudflare returned an invalid R2 lifecycle response");
  }
  return result["rules"];
}

async function verifyPrivacy(api: CloudflareApi): Promise<void> {
  const [managed, custom] = await Promise.all([
    api.request(`${bucketPath(api)}/domains/managed`),
    api.request(`${bucketPath(api)}/domains/custom`)
  ]);
  if (!isRecord(managed) || typeof managed["enabled"] !== "boolean") {
    throw new Error("Cloudflare returned an invalid R2 managed-domain response");
  }
  if (managed["enabled"]) {
    throw new Error("R2 public access through r2.dev must be disabled");
  }
  if (!isRecord(custom) || !Array.isArray(custom["domains"])) {
    throw new Error("Cloudflare returned an invalid R2 custom-domain response");
  }
  if (custom["domains"].length !== 0) {
    throw new Error("R2 bucket must not have custom domains");
  }
}

async function verify(api: CloudflareApi): Promise<void> {
  await verifyPrivacy(api);
  verifyLifecycleRules(await readLifecycleRules(api));
  console.log(`Verified private R2 bucket and lifecycle policy: ${CIPHERTEXT_BUCKET_NAME}`);
}

async function reconcile(api: CloudflareApi): Promise<void> {
  await ensureBucket(api);
  await verifyPrivacy(api);
  const currentRules = await readLifecycleRules(api);
  const result = reconcileLifecycleRules(currentRules);
  if (result.changed) {
    await api.request(`${bucketPath(api)}/lifecycle`, {
      body: JSON.stringify({ rules: result.rules }),
      method: "PUT"
    });
    console.log(`Reconciled R2 lifecycle policy: ${CIPHERTEXT_BUCKET_NAME}`);
  } else {
    console.log(`R2 lifecycle policy is current: ${CIPHERTEXT_BUCKET_NAME}`);
  }
  await verify(api);
}

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command !== "reconcile" && command !== "verify") {
    throw new Error("Usage: bun tools/infrastructure/r2.ts reconcile|verify");
  }
  const api = cloudflareApiFromEnvironment();
  if (command === "reconcile") {
    await reconcile(api);
  } else {
    await verify(api);
  }
}

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "Infrastructure command failed");
  process.exitCode = 1;
}
