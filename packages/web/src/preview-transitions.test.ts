import { describe, expect, it } from "vitest";

import type { KryptexAdapter, PreviewEnvelope, PreviewOperation, PreviewOutcome, PreviewRequestSchema, PreviewRunRequest } from "./preview-adapter";
import { createPreviewEnvelope, reconcileCreation, reconcilePickup, submitIdenticalEnvelope } from "./preview-transitions";

interface ScriptStep {
  readonly error?: string;
  readonly operation: PreviewOperation;
  readonly outcome?: PreviewOutcome;
}

interface RecordedCall {
  readonly operation: PreviewOperation;
  readonly request: PreviewRunRequest | undefined;
}

function createScriptedAdapter(steps: readonly ScriptStep[]): { readonly adapter: KryptexAdapter; readonly calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  let index = 0;
  const schema: PreviewRequestSchema = { fields: [], instructions: "", title: "Scripted" };
  const adapter: KryptexAdapter = {
    run(operation, request) {
      const step = steps[index];
      index += 1;
      calls.push({ operation, request });
      if (step === undefined) return Promise.reject(new Error("Unexpected preview operation"));
      if (step.operation !== operation) return Promise.reject(new Error(`Expected ${step.operation}, received ${operation}`));
      if (step.error !== undefined) return Promise.reject(new Error(step.error));
      return Promise.resolve({ operation, outcome: step.outcome ?? "ok", simulated: true });
    },
    readRequestSchema() { return schema; },
    rememberRequestSchema() { return undefined; }
  };
  return { adapter, calls };
}

describe("safe preview transitions", () => {
  it("reconciles an ambiguous create response without creating again", async () => {
    const scripted = createScriptedAdapter([
      { error: "ambiguous", operation: "create-send" },
      { operation: "create-status", outcome: "created" }
    ]);
    await expect(scripted.adapter.run("create-send")).rejects.toThrow("ambiguous");
    await expect(reconcileCreation(scripted.adapter)).resolves.toBe("created");
    expect(scripted.calls.map((call) => call.operation)).toEqual(["create-send", "create-status"]);
  });

  it("labels absence and unavailable creation status", async () => {
    const absent = createScriptedAdapter([{ operation: "create-status", outcome: "absent" }]);
    const unavailable = createScriptedAdapter([{ operation: "create-status", outcome: "unavailable" }]);
    await expect(reconcileCreation(absent.adapter)).resolves.toBe("absent");
    await expect(reconcileCreation(unavailable.adapter)).resolves.toBe("unavailable");
  });

  it("checks pickup status before allowing another consuming pickup", async () => {
    const scripted = createScriptedAdapter([
      { error: "ambiguous", operation: "pickup" },
      { operation: "pickup-status", outcome: "submitted" },
      { operation: "pickup", outcome: "opened" }
    ]);
    await expect(scripted.adapter.run("pickup")).rejects.toThrow("ambiguous");
    await expect(reconcilePickup(scripted.adapter)).resolves.toBe("retry");
    await scripted.adapter.run("pickup");
    expect(scripted.calls.map((call) => call.operation)).toEqual(["pickup", "pickup-status", "pickup"]);
  });

  it("reaches waiting, terminal, and unavailable pickup states", async () => {
    const waiting = createScriptedAdapter([{ operation: "pickup-status", outcome: "waiting" }]);
    const opened = createScriptedAdapter([{ operation: "pickup-status", outcome: "opened" }]);
    const unavailable = createScriptedAdapter([{ operation: "pickup-status", outcome: "unavailable" }]);
    await expect(reconcilePickup(waiting.adapter)).resolves.toBe("waiting");
    await expect(reconcilePickup(opened.adapter)).resolves.toBe("opened");
    await expect(reconcilePickup(unavailable.adapter)).resolves.toBe("unavailable");
  });

  it("retries the identical response envelope after ambiguity", async () => {
    const scripted = createScriptedAdapter([
      { error: "ambiguous", operation: "submit" },
      { operation: "submit", outcome: "ok" }
    ]);
    const envelope: PreviewEnvelope = createPreviewEnvelope();
    await expect(submitIdenticalEnvelope(scripted.adapter, envelope)).rejects.toThrow("ambiguous");
    await submitIdenticalEnvelope(scripted.adapter, envelope);
    expect(scripted.calls[0]?.request?.envelope).toBe(envelope);
    expect(scripted.calls[1]?.request?.envelope).toBe(envelope);
  });

  it("makes a retrieval retry an explicit second consuming call", async () => {
    const scripted = createScriptedAdapter([
      { error: "ambiguous", operation: "retrieve" },
      { operation: "retrieve", outcome: "opened" }
    ]);
    await expect(scripted.adapter.run("retrieve")).rejects.toThrow("ambiguous");
    await scripted.adapter.run("retrieve");
    expect(scripted.calls.map((call) => call.operation)).toEqual(["retrieve", "retrieve"]);
  });
});
