import { randomBytes } from "node:crypto";
import { closeSync, constants, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { CliError } from "./errors.js";
import { parseRecord, type OperationRecord } from "./record.js";

const HANDLE_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
const HANDLE_PATTERN = /^[0-9a-hjkmnp-tv-z]{10}$/u;

export function stateDirectory(environment: Readonly<Record<string, string | undefined>>): string {
  const explicit = environment["KRYPTEX_STATE_DIR"];
  if (explicit !== undefined && explicit.length > 0) return explicit;
  const xdg = environment["XDG_STATE_HOME"];
  return xdg !== undefined && xdg.length > 0 ? join(xdg, "kryptex") : join(homedir(), ".local", "state", "kryptex");
}

/** Creates the directory on first use and refuses one that another user could read or replace. */
export function openStore(directory: string): string {
  mkdirSync(directory, { mode: 0o700, recursive: true });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) {
    throw new CliError("state_invalid");
  }
  return directory;
}

export function newHandle(): string {
  return Array.from(randomBytes(10), (byte) => HANDLE_ALPHABET[byte & 31] ?? "").join("");
}

export function isHandle(value: string): boolean {
  return HANDLE_PATTERN.test(value);
}

function recordPath(directory: string, handle: string): string {
  if (!isHandle(handle)) throw new CliError("state_invalid");
  return join(directory, `${handle}.json`);
}

export function syncDirectory(directory: string): void {
  const descriptor = openSync(directory, constants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

/** Writes through an exclusive temporary file, syncs, and renames, so a crash leaves the old or the new record. */
export function writeFileAtomic(target: string, content: string): void {
  const directory = dirname(target);
  const temporary = join(directory, `.${basename(target)}.${randomBytes(6).toString("hex")}.kryptex-tmp`);
  const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeSync(descriptor, content);
    fsyncSync(descriptor);
  } catch (error) {
    closeSync(descriptor);
    unlinkSync(temporary);
    throw error;
  }
  closeSync(descriptor);
  try {
    renameSync(temporary, target);
  } catch (error) {
    unlinkSync(temporary);
    throw error;
  }
  syncDirectory(directory);
}

export function readRecord(directory: string, handle: string): OperationRecord {
  let text: string;
  try {
    const descriptor = openSync(recordPath(directory, handle), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      text = readFileSync(descriptor, "utf8");
    } finally {
      closeSync(descriptor);
    }
  } catch {
    throw new CliError("state_invalid");
  }
  try {
    const record = parseRecord(JSON.parse(text));
    if (record.handle !== handle) throw new CliError("state_invalid");
    return record;
  } catch {
    throw new CliError("state_invalid");
  }
}

export function writeRecord(directory: string, record: OperationRecord): void {
  writeFileAtomic(recordPath(directory, record.handle), `${JSON.stringify(record)}\n`);
}

export function deleteRecord(directory: string, handle: string): void {
  unlinkSync(recordPath(directory, handle));
  syncDirectory(directory);
}

export function listHandles(directory: string): readonly string[] {
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .map((name) => name.slice(0, -".json".length))
    .filter(isHandle)
    .sort();
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error && "code" in error && error.code === "ESRCH");
  }
}

/** An exclusive lock file holding the owner's PID; a lock whose process is gone is taken over. */
export function acquireLock(directory: string, name: string): () => void {
  const path = join(directory, `${name}.lock`);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeSync(descriptor, String(process.pid));
      closeSync(descriptor);
      return () => {
        try {
          unlinkSync(path);
        } catch {
          // The lock is gone already; nothing else holds it.
        }
      };
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) throw new CliError("state_invalid");
      let holder = Number.NaN;
      try {
        holder = Number.parseInt(readFileSync(path, "utf8"), 10);
      } catch {
        // An unreadable lock is treated as held.
      }
      if (!Number.isSafeInteger(holder) || holder <= 0 || processAlive(holder)) throw new CliError("busy");
      unlinkSync(path);
    }
  }
  throw new CliError("busy");
}
