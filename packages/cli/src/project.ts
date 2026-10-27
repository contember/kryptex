import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, constants, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, writeSync, type Stats } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { CliError } from "./errors.js";
import { syncDirectory, writeFileAtomic } from "./store.js";

export function projectRoot(cwd: string): string {
  try {
    const output = execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return realpathSync(output.trim());
  } catch {
    throw new CliError("target_invalid");
  }
}

/** Resolves a command-line path against the creation directory and returns it relative to the project root. */
export function projectPath(root: string, cwd: string, input: string): string {
  const relativePath = relative(root, resolve(cwd, input));
  if (relativePath.length === 0 || relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new CliError("target_invalid");
  }
  return relativePath;
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    throw new CliError("target_invalid");
  }
}

function git(root: string, args: readonly string[]): number | null {
  return spawnSync("git", [...args], { cwd: root, stdio: "ignore" }).status;
}

export interface PathRules {
  readonly existence: "required" | "absent" | "either";
  readonly output: boolean;
}

/** Checks the path rules from the CLI spec; called at creation and again immediately before every read or write. */
export function checkProjectPath(root: string, relativePath: string, rules: PathRules): string {
  if (realpathSync(root) !== root) throw new CliError("target_invalid");
  const parts = relativePath.split(sep);
  let current = root;
  for (const part of parts.slice(0, -1)) {
    current = join(current, part);
    const stat = lstatOrNull(current);
    if (stat === null || stat.isSymbolicLink() || !stat.isDirectory()) throw new CliError("target_invalid");
  }
  const absolute = join(root, relativePath);
  const stat = lstatOrNull(absolute);
  if (stat === null ? rules.existence === "required" : rules.existence === "absent" || stat.isSymbolicLink() || !stat.isFile()) {
    throw new CliError("target_invalid");
  }
  if (rules.output) {
    if (git(root, ["check-ignore", "-q", "--", relativePath]) !== 0) throw new CliError("target_invalid");
    if (git(root, ["ls-files", "--error-unmatch", "--", relativePath]) === 0) throw new CliError("target_invalid");
  }
  return absolute;
}

export function readProjectFile(absolute: string): string | null {
  let descriptor: number;
  try {
    descriptor = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    throw new CliError("target_invalid");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(descriptor));
  } catch {
    throw new CliError("target_invalid");
  } finally {
    closeSync(descriptor);
  }
}

export function replaceProjectFile(absolute: string, content: string): void {
  writeFileAtomic(absolute, content);
}

/** Creates a file that must not exist yet, with mode 0600, and syncs it before returning. */
export function createProjectFile(absolute: string, content: string): void {
  const descriptor = openSync(absolute, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeSync(descriptor, content);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  syncDirectory(dirname(absolute));
}
