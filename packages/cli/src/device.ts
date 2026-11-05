import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { CliError } from "./errors.js";
import { acquireLock, syncDirectory, writeFileAtomic } from "./store.js";
import { base64UrlValue, exactObject, field, integerValue, ShapeError, stringValue } from "./validate.js";

export const DEVICE_FILE_VERSION = 1;

/** The only long-lived credential the CLI stores. It authorizes minting permits, never reading a transfer. */
export interface DeviceGrant {
  readonly deviceExpiresAt: number;
  readonly deviceLocator: string;
  readonly deviceToken: string;
  readonly origin: string;
  readonly version: 1;
}

export type DeviceFile =
  | { readonly state: "absent" }
  | { readonly state: "invalid" }
  | { readonly grant: DeviceGrant; readonly state: "present" };

function deviceName(origin: string): string {
  return createHash("sha256").update(origin).digest("hex");
}

/** Creates `devices/` on first use and refuses one that another user could read or replace. */
function deviceDirectory(store: string): string {
  const directory = join(store, "devices");
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) throw new CliError("state_invalid");
  }
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) {
    throw new CliError("state_invalid");
  }
  return directory;
}

function devicePath(store: string, origin: string): string {
  return join(deviceDirectory(store), `${deviceName(origin)}.json`);
}

function parseDeviceGrant(value: unknown, origin: string): DeviceGrant {
  const object = exactObject(value, ["deviceExpiresAt", "deviceLocator", "deviceToken", "origin", "version"], "device");
  if (field(object, "version") !== DEVICE_FILE_VERSION) throw new ShapeError("device.version");
  if (stringValue(field(object, "origin"), "device.origin") !== origin) throw new ShapeError("device.origin");
  return {
    deviceExpiresAt: integerValue(field(object, "deviceExpiresAt"), "device.deviceExpiresAt"),
    deviceLocator: base64UrlValue(field(object, "deviceLocator"), 16, "device.deviceLocator"),
    deviceToken: base64UrlValue(field(object, "deviceToken"), 32, "device.deviceToken"),
    origin,
    version: DEVICE_FILE_VERSION
  };
}

/** Reads the device file for an origin, ignoring its expiry. A file another user could read or replace is invalid. */
export function readDeviceFile(store: string, origin: string): DeviceFile {
  const path = devicePath(store, origin);
  let text: string;
  try {
    const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = fstatSync(descriptor);
      if (!stat.isFile() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) return { state: "invalid" };
      text = readFileSync(descriptor, "utf8");
    } finally {
      closeSync(descriptor);
    }
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return { state: "absent" };
    return { state: "invalid" };
  }
  try {
    return { grant: parseDeviceGrant(JSON.parse(text), origin), state: "present" };
  } catch {
    return { state: "invalid" };
  }
}

/** The grant operations may use: none when absent or expired by the local clock; an invalid file blocks the origin. */
export function usableDeviceGrant(store: string, origin: string, nowSeconds: number): DeviceGrant | null {
  const file = readDeviceFile(store, origin);
  if (file.state === "invalid") throw new CliError("state_invalid");
  if (file.state === "absent" || nowSeconds >= file.grant.deviceExpiresAt) return null;
  return file.grant;
}

/** Writing or deleting a device file holds this lock, keyed by the file name. */
export function acquireDeviceLock(store: string, origin: string): () => void {
  return acquireLock(store, `device-${deviceName(origin)}`);
}

export function withDeviceLock<T>(store: string, origin: string, action: () => T): T {
  const release = acquireDeviceLock(store, origin);
  try {
    return action();
  } finally {
    release();
  }
}

/** Replaces the device file atomically; the caller holds the device lock. */
export function writeDeviceFile(store: string, grant: DeviceGrant): void {
  writeFileAtomic(devicePath(store, grant.origin), `${JSON.stringify(grant)}\n`);
}

/** Removes the device file; the caller holds the device lock. Returns false when there was none. */
export function deleteDeviceFile(store: string, origin: string): boolean {
  const path = devicePath(store, origin);
  try {
    unlinkSync(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return false;
    throw new CliError("state_invalid");
  }
  syncDirectory(join(store, "devices"));
  return true;
}

/** Deletes the device file only while it still holds `deviceLocator`, so a grant paired meanwhile survives. */
export function forgetDeviceGrant(store: string, origin: string, deviceLocator: string): void {
  withDeviceLock(store, origin, () => {
    const file = readDeviceFile(store, origin);
    if (file.state === "present" && file.grant.deviceLocator === deviceLocator) deleteDeviceFile(store, origin);
  });
}
