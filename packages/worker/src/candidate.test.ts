import { afterEach, describe, expect, test } from "vitest";
import envelopeVectors from "../../../vectors/v1/envelopes.json";
import { parseKxe1Envelope } from "@kryptex/contracts/envelopes";
import { env } from "cloudflare:workers";
import { reset } from "cloudflare:test";
import { encodeBase64Url, unixSeconds } from "./core.js";
import {
  deleteEach,
  readVerifiedObjectWith,
  settleCandidate,
  uploadCandidateWith
} from "./r2.js";

afterEach(async () => {
  await reset();
});

function candidateEnvelope(timestamp: number): string {
  const vector = envelopeVectors.kxe1.find((candidate) => candidate.id === "send-none");
  if (vector === undefined) {
    throw new Error("missing send vector");
  }
  const bytes = Uint8Array.from(parseKxe1Envelope(vector.envelopeBase64url).bytes);
  new DataView(bytes.buffer).setBigUint64(8, BigInt(timestamp));
  return encodeBase64Url(bytes);
}

function value(length: number, fill: number): string {
  return encodeBase64Url(new Uint8Array(length).fill(fill));
}

async function candidateCount(): Promise<number> {
  return (await env.CIPHERTEXT.list({ prefix: "v1/candidates/" })).objects.length;
}

describe("candidate object commit protocol", () => {
  test("deletes definitive losers but preserves ambiguous outcomes", async () => {
    const candidate = { digest: "digest", key: "candidate", length: 1 };
    const deleted: string[] = [];
    const deleteCandidate = (key: string): Promise<boolean> => {
      deleted.push(key);
      return Promise.resolve(true);
    };

    await settleCandidate(
      candidate,
      () => Promise.resolve({ kind: "definitive_not_committed", value: 0 }),
      deleteCandidate
    );
    expect(deleted).toEqual(["candidate"]);

    await expect(settleCandidate(
      candidate,
      () => Promise.reject(new Error("ambiguous")),
      deleteCandidate
    )).rejects.toThrow("ambiguous");
    expect(deleted).toEqual(["candidate"]);
  });

  test("deletes a retry upload only when another candidate already won", async () => {
    const candidate = { digest: "digest", key: "retry", length: 1 };
    const deleted: string[] = [];
    const deleteCandidate = (key: string): Promise<boolean> => {
      deleted.push(key);
      return Promise.resolve(true);
    };

    await settleCandidate(
      candidate,
      () => Promise.resolve({ kind: "committed", value: 1, winnerKey: "winner" }),
      deleteCandidate
    );
    await settleCandidate(
      candidate,
      () => Promise.resolve({ kind: "committed", value: 1, winnerKey: "retry" }),
      deleteCandidate
    );
    expect(deleted).toEqual(["retry"]);
  });

  test("reports partial deletion failure and still attempts every unique key", async () => {
    const attempted: string[] = [];
    const deleted = await deleteEach(["schema", "response", "response", "later"], (key) => {
      attempted.push(key);
      if (key === "schema" || key === "response") {
        return Promise.reject(new Error("R2 delete failed"));
      }
      return Promise.resolve();
    });
    expect(deleted).toBe(false);
    expect(attempted).toEqual(["schema", "response", "later"]);
  });

  test("propagates R2 put and get failures and rejects corrupt objects", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    await expect(uploadCandidateWith(bytes, "candidate", () => {
      return Promise.reject(new Error("R2 put failed"));
    })).rejects.toThrow("R2 put failed");

    const metadata = await uploadCandidateWith(bytes, "candidate", () => Promise.resolve());
    await expect(readVerifiedObjectWith(metadata, () => {
      return Promise.reject(new Error("R2 get failed"));
    })).rejects.toThrow("R2 get failed");
    expect(await readVerifiedObjectWith(metadata, () => Promise.resolve(new Uint8Array([1, 2, 4])))).toBeNull();
    expect(await readVerifiedObjectWith(metadata, () => Promise.resolve(new Uint8Array([1, 2])))).toBeNull();
  });

  test("keeps only the winning candidate and makes attempt retries idempotent", async () => {
    const now = unixSeconds();
    const locator = value(16, 81);
    const shared = {
      clientNotAfter: now + 900,
      envelope: candidateEnvelope(now + 900),
      locator,
      manageToken: value(32, 82),
      maxRetrievals: 1,
      retrieveToken: value(32, 83),
      settleNotAfter: now + 30,
      ttlSeconds: 900
    };
    const first = { ...shared, attemptId: value(16, 84) };
    const second = { ...shared, attemptId: value(16, 85) };
    const stub = env.SEND_OBJECTS.getByName(locator);
    const before = await candidateCount();
    const results = await Promise.all([
      stub.fetch("https://durable-object.invalid/init", {
        body: JSON.stringify(first),
        headers: { "Content-Type": "application/json" },
        method: "POST"
      }),
      stub.fetch("https://durable-object.invalid/init", {
        body: JSON.stringify(second),
        headers: { "Content-Type": "application/json" },
        method: "POST"
      })
    ]);
    expect(results.filter((response) => response.status === 200)).toHaveLength(1);
    expect(results.filter((response) => response.status === 404)).toHaveLength(1);
    expect(await candidateCount()).toBe(before + 1);

    const winner = results[0].status === 200 ? first : second;
    const loser = results[0].status === 404 ? first : second;
    const retryWinner = await stub.fetch("https://durable-object.invalid/init", {
      body: JSON.stringify(winner),
      headers: { "Content-Type": "application/json" },
      method: "POST"
    });
    const retryLoser = await stub.fetch("https://durable-object.invalid/init", {
      body: JSON.stringify(loser),
      headers: { "Content-Type": "application/json" },
      method: "POST"
    });
    expect(retryWinner.status).toBe(200);
    expect(retryLoser.status).toBe(404);
    expect(await candidateCount()).toBe(before + 1);
  });
});
