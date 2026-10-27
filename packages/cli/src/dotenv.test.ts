import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { checkDotenvTargets, encodeDotenvValue, readDotenvKeys, upsertDotenv } from "./dotenv.js";
import type { Dialect } from "./record.js";

const directory = mkdtempSync(join(tmpdir(), "kryptex-dotenv-"));
afterAll(() => {
  rmSync(directory, { force: true, recursive: true });
});

const VALUES = [
  "plain",
  "with spaces and # hash",
  "sk-live_0123456789abcdefABCDEF",
  "dollar $HOME and ${PATH} and $",
  "it's single",
  "back`tick",
  "both ' and ` quotes $HOME",
  "all ' and ` and \" quotes",
  "ends with a dollar $",
  "ends with two dollars $$",
  "dollar at line end $\nnext",
  "multi\nline\nvalue",
  "trailing backslash \\",
  "backslash \\n not a newline",
  "equals=and \"double\" quotes",
  "unicode žluťoučký 🐎",
  "  padded  "
];

/** Loads `file` with a real runtime and prints the parsed value of KX_VALUE. */
function runtimeValue(command: "bun" | "node", file: string): string {
  const script = "process.stdout.write(JSON.stringify(process.env.KX_VALUE ?? null))";
  const result = spawnSync(command, [`--env-file=${file}`, "-e", script], {
    cwd: directory,
    encoding: "utf8"
  });
  expect(result.status).toBe(0);
  const parsed: unknown = JSON.parse(result.stdout);
  expect(typeof parsed).toBe("string");
  return typeof parsed === "string" ? parsed : "";
}

function encodable(value: string, dialect: Dialect): boolean {
  try {
    encodeDotenvValue(value, dialect);
    return true;
  } catch {
    return false;
  }
}

describe.each<[Dialect, "bun" | "node"]>([["expand", "bun"], ["literal", "node"]])("dialect %s", (dialect, runtime) => {
  const accepted = VALUES.filter((value) => encodable(value, dialect));

  it("rejects only the samples the dialect cannot carry", () => {
    const rejected = dialect === "expand" ? ["all ' and ` and \" quotes", "trailing backslash \\"] : ["all ' and ` and \" quotes"];
    expect(VALUES.filter((value) => !accepted.includes(value))).toEqual(rejected);
  });

  it.each(accepted)("round-trips %j through the dotenv package and the runtime", (value) => {
    const content = upsertDotenv("", new Map([["KX_VALUE", value]]), dialect);
    expect(readDotenvKeys(content, dialect, ["KX_VALUE"]).get("KX_VALUE")).toBe(value);
    const file = join(directory, `${dialect}.env`);
    writeFileSync(file, content);
    expect(runtimeValue(runtime, file)).toBe(value);
  });
});

describe("encodeDotenvValue", () => {
  it("rejects values no dialect can carry", () => {
    for (const dialect of ["expand", "literal"] as const) {
      expect(() => encodeDotenvValue("nul\0", dialect)).toThrow(expect.objectContaining({ code: "env_value_unrepresentable" }));
      expect(() => encodeDotenvValue("cr\r", dialect)).toThrow(expect.objectContaining({ code: "env_value_unrepresentable" }));
    }
  });

  it("rejects an escaped dollar only in the expand dialect", () => {
    expect(() => encodeDotenvValue("a\\$b", "expand")).toThrow(expect.objectContaining({ code: "env_value_unrepresentable" }));
    expect(encodeDotenvValue("a\\$b", "literal")).toBe("'a\\$b'");
  });
});

describe("upsertDotenv", () => {
  it("replaces a single-line assignment in place and appends new keys", () => {
    const existing = "# config\nexport API_KEY=old\nOTHER='keep'\n";
    const updated = upsertDotenv(existing, new Map([["API_KEY", "new"], ["ADDED", "x"]]), "literal");
    expect(updated).toBe("# config\nAPI_KEY='new'\nOTHER='keep'\nADDED='x'\n");
  });

  it("adds the missing final newline before appending", () => {
    expect(upsertDotenv("A=1", new Map([["B", "2"]]), "literal")).toBe("A=1\nB='2'\n");
  });

  it("leaves lines inside a multi-line value of another key alone", () => {
    const existing = "CERT='line one\nAPI_KEY=not a key\n'\n";
    const updated = upsertDotenv(existing, new Map([["API_KEY", "v"]]), "literal");
    expect(updated).toBe("CERT='line one\nAPI_KEY=not a key\n'\nAPI_KEY='v'\n");
  });

  it("refuses a target that is assigned twice or spans several lines", () => {
    expect(() => {
      checkDotenvTargets("API_KEY=a\nAPI_KEY=b\n", ["API_KEY"]);
    }).toThrow(expect.objectContaining({ code: "env_file_conflict" }));
    expect(() => {
      checkDotenvTargets("API_KEY='a\nb'\n", ["API_KEY"]);
    }).toThrow(expect.objectContaining({ code: "env_file_conflict" }));
  });
});

describe("readDotenvKeys", () => {
  it("expands only from the same file in the expand dialect", () => {
    const content = "BASE=abc\nFULL=${BASE}-x\nHOMELESS=$HOME\n";
    const expanded = readDotenvKeys(content, "expand", ["FULL"]);
    expect(expanded.get("FULL")).toBe("abc-x");
    expect(() => readDotenvKeys(content, "expand", ["HOMELESS"])).toThrow(expect.objectContaining({ code: "source_invalid" }));
    expect(readDotenvKeys(content, "literal", ["FULL"]).get("FULL")).toBe("${BASE}-x");
  });

  it("rejects a missing or empty key", () => {
    expect(() => readDotenvKeys("A=\n", "literal", ["A"])).toThrow(expect.objectContaining({ code: "source_invalid" }));
    expect(() => readDotenvKeys("A=1\n", "literal", ["B"])).toThrow(expect.objectContaining({ code: "source_invalid" }));
  });
});
