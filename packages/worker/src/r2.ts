import { digestBase64Url, randomBase64Url } from "./core.js";
import type { ObjectMetadata } from "./state.js";

export async function uploadCandidate(bucket: R2Bucket, bytes: Uint8Array): Promise<ObjectMetadata> {
  const key = `v1/candidates/${randomBase64Url(32)}`;
  return uploadCandidateWith(bytes, key, async (candidateKey, candidateBytes) => {
    await bucket.put(candidateKey, candidateBytes, {
      httpMetadata: { contentType: "application/octet-stream" }
    });
  });
}

export async function uploadCandidateWith(
  bytes: Uint8Array,
  key: string,
  putObject: (key: string, bytes: Uint8Array) => Promise<void>
): Promise<ObjectMetadata> {
  const digest = await digestBase64Url(bytes);
  await putObject(key, bytes);
  return { digest, key, length: bytes.byteLength };
}

export async function readVerifiedObject(bucket: R2Bucket, metadata: ObjectMetadata): Promise<Uint8Array | null> {
  return readVerifiedObjectWith(metadata, async (key) => {
    const object = await bucket.get(key);
    if (object?.size !== metadata.length) {
      return null;
    }
    return new Uint8Array(await object.arrayBuffer());
  });
}

export async function readVerifiedObjectWith(
  metadata: ObjectMetadata,
  getObject: (key: string) => Promise<Uint8Array | null>
): Promise<Uint8Array | null> {
  const bytes = await getObject(metadata.key);
  if (bytes === null) {
    return null;
  }
  if (bytes.byteLength !== metadata.length || (await digestBase64Url(bytes)) !== metadata.digest) {
    return null;
  }
  return bytes;
}

export async function deleteKeys(bucket: R2Bucket, keys: readonly string[]): Promise<boolean> {
  return deleteEach(keys, async (key) => bucket.delete(key));
}

export async function deleteEach(
  keys: readonly string[],
  deleteObject: (key: string) => Promise<void>
): Promise<boolean> {
  let succeeded = true;
  for (const key of new Set(keys)) {
    try {
      await deleteObject(key);
    } catch {
      succeeded = false;
    }
  }
  return succeeded;
}

export type CandidateDecision<T> =
  | { readonly kind: "committed"; readonly value: T; readonly winnerKey: string }
  | { readonly kind: "definitive_not_committed"; readonly value: T };

export async function settleCandidate<T>(
  candidate: ObjectMetadata,
  decide: () => Promise<CandidateDecision<T>>,
  deleteCandidate: (key: string) => Promise<boolean>
): Promise<CandidateDecision<T>> {
  const decision = await decide();
  if (decision.kind === "definitive_not_committed" || decision.winnerKey !== candidate.key) {
    await deleteCandidate(candidate.key);
  }
  return decision;
}
