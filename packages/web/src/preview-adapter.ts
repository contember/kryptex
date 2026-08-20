export type PreviewOperation =
  | "authorize"
  | "gate-status"
  | "create-status"
  | "create-send"
  | "create-request"
  | "retrieve"
  | "inspect"
  | "submit"
  | "pickup"
  | "pickup-status"
  | "shorten"
  | "revoke";

export type PreviewOutcome =
  | "ok"
  | "ready"
  | "pending"
  | "created"
  | "absent"
  | "submitted"
  | "opened"
  | "waiting"
  | "unavailable";

export interface PreviewEnvelope {
  readonly previewId: string;
}

export interface PreviewRunRequest {
  readonly envelope?: PreviewEnvelope;
}

export interface PreviewResult {
  readonly operation: PreviewOperation;
  readonly outcome: PreviewOutcome;
  readonly simulated: true;
}

export type PreviewFieldType = "short" | "secret" | "long";

export interface PreviewRequestField {
  readonly help: string;
  readonly id: number;
  readonly label: string;
  readonly required: boolean;
  readonly type: PreviewFieldType;
}

export interface PreviewRequestSchema {
  readonly fields: readonly PreviewRequestField[];
  readonly instructions: string;
  readonly title: string;
}

export interface KryptexAdapter {
  run(operation: PreviewOperation, request?: PreviewRunRequest): Promise<PreviewResult>;
  readRequestSchema(): PreviewRequestSchema;
  rememberRequestSchema(schema: PreviewRequestSchema): void;
}

function waitForPreview(): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, 260));
}

let requestSchema: PreviewRequestSchema = {
  fields: [
    { help: "Paste the complete value without surrounding quotes.", id: 1, label: "API key", required: true, type: "secret" }
  ],
  instructions: "Add the key ID in the note if available.",
  title: "Production access handoff"
};

export const localPreviewAdapter: KryptexAdapter = {
  async run(operation) {
    await waitForPreview();
    const outcome: PreviewOutcome = operation === "gate-status"
      ? "ready"
      : operation === "create-status"
        ? "created"
        : operation === "pickup-status"
          ? "submitted"
          : "ok";
    return { operation, outcome, simulated: true };
  },
  readRequestSchema() {
    return requestSchema;
  },
  rememberRequestSchema(schema) {
    requestSchema = schema;
  }
};
