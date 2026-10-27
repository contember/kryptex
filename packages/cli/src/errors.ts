export type ErrorCode =
  | "busy"
  | "network"
  | "rate_limited"
  | "unavailable"
  | "expired"
  | "revoked"
  | "pickup_lost"
  | "answer_invalid"
  | "target_invalid"
  | "env_file_conflict"
  | "env_value_unrepresentable"
  | "source_invalid"
  | "exec_failed"
  | "handoff_failed"
  | "state_invalid"
  | "internal";

const DETAILS: Readonly<Record<ErrorCode, { readonly message: string; readonly retryable: boolean }>> = {
  answer_invalid: { message: "The received answer failed authentication or does not match this request.", retryable: false },
  busy: { message: "Another kryptex command is working on this operation or output file.", retryable: true },
  env_file_conflict: { message: "The dotenv file assigns a target more than once or across several lines. Fix the file, then run wait again.", retryable: true },
  env_value_unrepresentable: { message: "A received value has no safe encoding in the chosen dotenv dialect. The answer is kept; discard the operation or edit the file manually.", retryable: true },
  exec_failed: { message: "The command failed to start or exited with a non-zero code. Run wait again to repeat it.", retryable: true },
  expired: { message: "The resource expired before the operation finished.", retryable: false },
  handoff_failed: { message: "The hand-off file could not be written. Run wait again.", retryable: true },
  internal: { message: "An unexpected failure occurred.", retryable: false },
  network: { message: "The service could not be reached. Run wait again.", retryable: true },
  pickup_lost: { message: "The answer was released by the service but not received. It cannot be recovered.", retryable: false },
  rate_limited: { message: "The service asked the client to slow down. Run wait again later.", retryable: true },
  revoked: { message: "The resource was revoked.", retryable: false },
  source_invalid: { message: "A source key is missing or empty, or the source file cannot be read.", retryable: true },
  state_invalid: { message: "The operation state is missing or invalid.", retryable: false },
  target_invalid: { message: "An input or output path does not satisfy the path rules: inside the Git project, no symbolic links, and for outputs ignored and untracked by Git.", retryable: true },
  unavailable: { message: "The resource is unavailable: missing, expired, revoked, or no longer accepting this operation.", retryable: false }
};

/** Carries only a fixed code. Messages never include input, file contents, or exception text. */
export class CliError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode) {
    super(DETAILS[code].message);
    this.name = "CliError";
    this.code = code;
  }
}

/** A command-line mistake; the message is always a literal from this package, never user input. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export function errorDetails(code: ErrorCode): { readonly message: string; readonly retryable: boolean } {
  return DETAILS[code];
}
