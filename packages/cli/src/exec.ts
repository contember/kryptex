import { spawn } from "node:child_process";

export interface RedactedValue {
  readonly target: string;
  readonly value: string;
}

/**
 * Replaces exact byte occurrences of each value with `[redacted:TARGET]` in a stream.
 * It keeps a carry one byte shorter than the longest value, so an occurrence split across chunks is still caught.
 */
export class Redactor {
  readonly #values: readonly { readonly bytes: Buffer; readonly replacement: Buffer }[];
  readonly #longest: number;
  #carry: Buffer = Buffer.alloc(0);

  constructor(values: readonly RedactedValue[]) {
    this.#values = values
      .filter((entry) => entry.value.length > 0)
      .map((entry) => ({ bytes: Buffer.from(entry.value, "utf8"), replacement: Buffer.from(`[redacted:${entry.target}]`, "utf8") }))
      .sort((left, right) => right.bytes.byteLength - left.bytes.byteLength);
    this.#longest = this.#values[0]?.bytes.byteLength ?? 0;
  }

  push(chunk: Buffer): Buffer {
    return this.#scan(Buffer.concat([this.#carry, chunk]), false);
  }

  end(): Buffer {
    return this.#scan(this.#carry, true);
  }

  #scan(data: Buffer, final: boolean): Buffer {
    const output: Buffer[] = [];
    const decidable = final ? data.byteLength : data.byteLength - (this.#longest - 1);
    let start = 0;
    let index = 0;
    while (index < decidable) {
      const match = this.#values.find((entry) => data.subarray(index, index + entry.bytes.byteLength).equals(entry.bytes));
      if (match === undefined) {
        index += 1;
        continue;
      }
      output.push(data.subarray(start, index), match.replacement);
      index += match.bytes.byteLength;
      start = index;
    }
    const safeEnd = Math.max(start, Math.min(index, data.byteLength));
    output.push(data.subarray(start, safeEnd));
    this.#carry = Buffer.from(data.subarray(safeEnd));
    return Buffer.concat(output);
  }
}

export interface ExecResult {
  readonly exitCode: number | null;
}

/** Runs the recorded command with the values in its environment and forwards its redacted output to `sink`. */
export function runRedacted(
  argv: readonly string[],
  cwd: string,
  environment: Readonly<Record<string, string>>,
  values: readonly RedactedValue[],
  sink: (chunk: Buffer) => void
): Promise<ExecResult> {
  const [command, ...args] = argv;
  if (command === undefined) return Promise.resolve({ exitCode: null });
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"] });
    const streams = [child.stdout, child.stderr];
    let open = streams.length;
    let exitCode: number | null = null;
    let exited = false;
    const finish = (): void => {
      if (exited && open === 0) resolve({ exitCode });
    };
    for (const stream of streams) {
      const redactor = new Redactor(values);
      stream.on("data", (chunk: Buffer) => { sink(redactor.push(chunk)); });
      stream.on("close", () => { sink(redactor.end()); open -= 1; finish(); });
    }
    child.on("error", () => { exitCode = null; exited = true; open = 0; resolve({ exitCode: null }); });
    child.on("close", (code) => { exitCode = code; exited = true; finish(); });
  });
}
