import { useState } from "react";

import type { PreviewOperation, PreviewResult, PreviewRunRequest } from "./preview-adapter";
import { usePreviewAdapter } from "./preview-context";

type OperationPhase = "idle" | "working" | "done";

export function usePreviewOperation() {
  const [phase, setPhase] = useState<OperationPhase>("idle");
  const adapter = usePreviewAdapter();

  async function run(operation: PreviewOperation, request?: PreviewRunRequest): Promise<PreviewResult> {
    setPhase("working");
    const result = await adapter.run(operation, request);
    setPhase("done");
    return result;
  }

  function reset(): void {
    setPhase("idle");
  }

  return { adapter, phase, reset, run };
}
