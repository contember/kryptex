import { parse } from "dotenv";
import { expand } from "dotenv-expand";
import { CliError } from "./errors.js";
import type { Dialect } from "./record.js";

/** Encodes one value so the dialect's parsers read it back exactly; see "Dotenv upsert" in docs/spec/cli-v1.md. */
export function encodeDotenvValue(value: string, dialect: Dialect): string {
  if (value.includes("\0") || value.includes("\r")) throw new CliError("env_value_unrepresentable");
  // Bun keeps `\$` literal before the closing quote and reads a final backslash as escaping that quote.
  if (dialect === "expand" && (value.includes("\\$") || value.endsWith("\\"))) throw new CliError("env_value_unrepresentable");
  const escaped = dialect === "expand" ? value.replace(/\$(?=[\s\S])/gu, () => "\\$") : value;
  if (!value.includes("'")) return `'${escaped}'`;
  if (!value.includes("`")) return `\`${escaped}\``;
  if (!value.includes("\"") && !value.includes("\\") && !value.includes("\n")) return `"${escaped}"`;
  throw new CliError("env_value_unrepresentable");
}

interface Assignment {
  readonly endLine: number;
  readonly key: string;
  readonly startLine: number;
}

const ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/u;

/** Index of the closing quote in `text`, honoring backslash escapes, or -1. */
function closingQuote(text: string, quote: string, from: number): number {
  for (let index = from; index < text.length; index += 1) {
    if (text[index] === "\\") index += 1;
    else if (text[index] === quote) return index;
  }
  return -1;
}

/** Finds every assignment and how many lines its value spans, so lines inside a quoted value are never taken for keys. */
function assignments(lines: readonly string[]): readonly Assignment[] {
  const output: Assignment[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = ASSIGNMENT.exec(lines[index] ?? "");
    if (match === null) continue;
    const key = match[1] ?? "";
    const value = match[2] ?? "";
    const quote = value[0];
    let endLine = index;
    if ((quote === "'" || quote === "\"" || quote === "`") && closingQuote(value, quote, 1) < 0) {
      let next = index + 1;
      while (next < lines.length && closingQuote(lines[next] ?? "", quote, 0) < 0) next += 1;
      endLine = Math.min(next, lines.length - 1);
    }
    output.push({ endLine, key, startLine: index });
    index = endLine;
  }
  return output;
}

/** Fails with env_file_conflict when a target cannot be replaced safely. Run before pickup and again before writing. */
export function checkDotenvTargets(existing: string, targets: readonly string[]): void {
  const found = assignments(existing.split("\n"));
  for (const target of targets) {
    const matches = found.filter((assignment) => assignment.key === target);
    if (matches.length > 1 || matches.some((assignment) => assignment.endLine !== assignment.startLine)) {
      throw new CliError("env_file_conflict");
    }
  }
}

export function upsertDotenv(existing: string, entries: ReadonlyMap<string, string>, dialect: Dialect): string {
  checkDotenvTargets(existing, [...entries.keys()]);
  const lines = existing.length === 0 ? [] : existing.split("\n");
  const trailingNewline = lines.length > 0 && lines[lines.length - 1] === "";
  if (trailingNewline) lines.pop();
  const replaced = new Set<string>();
  for (const assignment of assignments(lines)) {
    const value = entries.get(assignment.key);
    if (value === undefined) continue;
    lines[assignment.startLine] = `${assignment.key}=${encodeDotenvValue(value, dialect)}`;
    replaced.add(assignment.key);
  }
  for (const [key, value] of entries) {
    if (!replaced.has(key)) lines.push(`${key}=${encodeDotenvValue(value, dialect)}`);
  }
  return `${lines.join("\n")}\n`;
}

/** Reads named keys from a dotenv file. `expand` resolves variables only from the same file, never from the environment. */
export function readDotenvKeys(content: string, dialect: Dialect, keys: readonly string[]): ReadonlyMap<string, string> {
  let parsed: Record<string, string>;
  try {
    parsed = parse(content);
    if (dialect === "expand") {
      const expanded = expand({ parsed: { ...parsed }, processEnv: {} }).parsed;
      if (expanded === undefined) throw new CliError("source_invalid");
      parsed = expanded;
    }
  } catch {
    throw new CliError("source_invalid");
  }
  const output = new Map<string, string>();
  for (const key of keys) {
    const value = Object.hasOwn(parsed, key) ? parsed[key] : undefined;
    if (value === undefined || value.length === 0) throw new CliError("source_invalid");
    output.set(key, value);
  }
  return output;
}
