import { describe, expect, it } from "vitest";
import { Redactor, runRedacted } from "./exec.js";

function redactChunks(values: readonly { readonly target: string; readonly value: string }[], chunks: readonly string[]): string {
  const redactor = new Redactor(values);
  const output = chunks.map((chunk) => redactor.push(Buffer.from(chunk, "utf8")));
  output.push(redactor.end());
  return Buffer.concat(output).toString("utf8");
}

describe("Redactor", () => {
  const secret = { target: "API_KEY", value: "sk-0123456789" };
  const text = `before ${secret.value} middle ${secret.value} after`;
  const expected = "before [redacted:API_KEY] middle [redacted:API_KEY] after";

  it("catches a value split at every byte boundary", () => {
    for (let split = 0; split <= text.length; split += 1) {
      expect(redactChunks([secret], [text.slice(0, split), text.slice(split)])).toBe(expected);
    }
  });

  it("catches a value fed one byte at a time", () => {
    expect(redactChunks([secret], Array.from({ length: text.length }, (_, index) => text.slice(index, index + 1)))).toBe(expected);
  });

  it("prefers the longest value when one contains another", () => {
    const values = [{ target: "SHORT", value: "abc" }, { target: "LONG", value: "abcdef" }];
    expect(redactChunks(values, ["x abcdef y abc z"])).toBe("x [redacted:LONG] y [redacted:SHORT] z");
  });

  it("matches multi-byte values exactly", () => {
    const values = [{ target: "WORD", value: "žluťoučký" }];
    const bytes = Buffer.from("a žluťoučký b", "utf8");
    const redactor = new Redactor(values);
    const output = [...bytes].map((byte) => redactor.push(Buffer.from([byte])));
    output.push(redactor.end());
    expect(Buffer.concat(output).toString("utf8")).toBe("a [redacted:WORD] b");
  });

  it("ignores empty values and passes text through unchanged", () => {
    expect(redactChunks([{ target: "EMPTY", value: "" }], ["plain ", "text"])).toBe("plain text");
  });
});

describe("runRedacted", () => {
  it("passes values in the environment and redacts both output streams", async () => {
    const chunks: Buffer[] = [];
    const result = await runRedacted(
      ["sh", "-c", "printf 'out %s\\n' \"$API_KEY\"; printf 'err %s\\n' \"$API_KEY\" >&2; exit 0"],
      process.cwd(),
      { API_KEY: "s3cr3t-value" },
      [{ target: "API_KEY", value: "s3cr3t-value" }],
      (chunk) => {
        chunks.push(chunk);
      }
    );
    expect(result.exitCode).toBe(0);
    const output = Buffer.concat(chunks).toString("utf8");
    expect(output).not.toContain("s3cr3t-value");
    expect(output).toContain("out [redacted:API_KEY]");
    expect(output).toContain("err [redacted:API_KEY]");
  });

  it("reports a non-zero exit code and a command that cannot start", async () => {
    expect((await runRedacted(["sh", "-c", "exit 7"], process.cwd(), {}, [], () => undefined)).exitCode).toBe(7);
    expect((await runRedacted(["kryptex-no-such-command"], process.cwd(), {}, [], () => undefined)).exitCode).toBeNull();
  });
});
