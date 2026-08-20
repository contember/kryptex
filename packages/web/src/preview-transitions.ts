import type { KryptexAdapter, PreviewEnvelope, PreviewOperation } from "./preview-adapter";

export type CreationReconciliation = "created" | "absent" | "unavailable";
export type PickupReconciliation = "retry" | "opened" | "waiting" | "unavailable";

export async function reconcileCreation(adapter: KryptexAdapter): Promise<CreationReconciliation> {
  try {
    const result = await adapter.run("create-status");
    if (result.outcome === "created") return "created";
    if (result.outcome === "absent") return "absent";
    return "unavailable";
  } catch {
    return "unavailable";
  }
}

export async function reconcilePickup(adapter: KryptexAdapter): Promise<PickupReconciliation> {
  try {
    const result = await adapter.run("pickup-status");
    if (result.outcome === "submitted") return "retry";
    if (result.outcome === "opened") return "opened";
    if (result.outcome === "waiting" || result.outcome === "pending") return "waiting";
    return "unavailable";
  } catch {
    return "unavailable";
  }
}

export async function submitIdenticalEnvelope(adapter: KryptexAdapter, envelope: PreviewEnvelope): Promise<void> {
  await adapter.run("submit", { envelope });
}

export function createPreviewEnvelope(): PreviewEnvelope {
  return { previewId: "UI_PREVIEW_ENVELOPE_NOT_CIPHERTEXT" };
}

export async function runConsumingOperation(adapter: KryptexAdapter, operation: Extract<PreviewOperation, "retrieve" | "pickup">): Promise<void> {
  await adapter.run(operation);
}
