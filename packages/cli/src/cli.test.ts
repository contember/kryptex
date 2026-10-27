import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseFormSpec, parseOrigin } from "./cli.js";
import { AGENT_INSTRUCTIONS } from "./skill.js";

const main = join(import.meta.dirname, "main.ts");

function spec(fields: readonly unknown[], title = "Credentials"): string {
  return JSON.stringify({ fields, title });
}

const secretField = { help: "", label: "API key", required: true, target: "API_KEY", type: "secret" };

describe("parseOrigin", () => {
  it("accepts https origins and plain-http localhost", () => {
    expect(parseOrigin("https://kryptex.example/")).toBe("https://kryptex.example");
    expect(parseOrigin("http://localhost:8787")).toBe("http://localhost:8787");
  });

  it("rejects anything but a bare origin", () => {
    for (const input of [undefined, "", "http://kryptex.example", "https://kryptex.example/api", "https://user@kryptex.example", "https://kryptex.example/?a", "ftp://kryptex.example"]) {
      expect(() => parseOrigin(input)).toThrow(expect.objectContaining({ name: "UsageError" }));
    }
  });
});

describe("parseFormSpec", () => {
  it("assigns protocol IDs in order and keeps targets local", () => {
    const parsed = parseFormSpec(spec([{ help: "", label: "Note", required: false, type: "instruction" }, secretField]));
    expect(parsed.fields.map((entry) => [entry.id, entry.target])).toEqual([["field001", null], ["field002", "API_KEY"]]);
  });

  it.each([
    ["extra keys", spec([{ ...secretField, extra: 1 }])],
    ["a missing target", spec([{ help: "", label: "Key", required: true, type: "secret" }])],
    ["a target on an instruction", spec([{ help: "", label: "Note", required: false, target: "X", type: "instruction" }])],
    ["only instructions", spec([{ help: "", label: "Note", required: false, type: "instruction" }])],
    ["a duplicate target", spec([secretField, { ...secretField, label: "Again" }])],
    ["an invalid target", spec([{ ...secretField, target: "API-KEY" }])],
    ["an empty title", spec([secretField], "")],
    ["a required instruction", spec([{ help: "", label: "Note", required: true, type: "instruction" }, secretField])],
    ["too many fields", spec(Array.from({ length: 33 }, (_, index) => ({ ...secretField, target: `K${index}` })))],
    ["invalid JSON", "{"]
  ])("rejects %s", (_name, text) => {
    expect(() => parseFormSpec(text)).toThrow(expect.objectContaining({ name: "UsageError" }));
  });
});

describe("kryptex skill", () => {
  it("prints exactly the instructions in the specification", () => {
    const specification = readFileSync(join(import.meta.dirname, "../../../docs/spec/cli-v1.md"), "utf8");
    const start = specification.indexOf("```markdown\n") + "```markdown\n".length;
    expect(AGENT_INSTRUCTIONS).toBe(specification.slice(start, specification.indexOf("\n```\n", start) + 1));
  });

  it("runs under Bun and prints the instructions", () => {
    const result = spawnSync("bun", [main, "skill"], { encoding: "utf8" });
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(AGENT_INSTRUCTIONS);
    expect(result.stderr).toBe("");
  });

  it("exits 2 with one JSON object on an unknown command", () => {
    const result = spawnSync("bun", [main, "unknown"], { encoding: "utf8" });
    expect(result.status).toBe(2);
    expect(JSON.parse(result.stdout)).toMatchObject({ error: "usage" });
    expect(result.stderr).toBe("");
  });
});
