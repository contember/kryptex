import { DEVICE_LINK_BYTE_LENGTH, DEVICE_LINK_MAGIC, DEVICE_LINK_VERSION } from "./protocol.js";
import { ContractValidationError, decodeCanonicalBase64Url } from "./validation.js";

/** The person's handle on one device grant, carried in the `/d` fragment. */
export interface DeviceLink {
  readonly deviceLocator: string;
  readonly manageToken: string;
}

const MAGIC_BYTES = new TextEncoder().encode(DEVICE_LINK_MAGIC);

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function decodeExact(value: string, length: number, context: string): Uint8Array {
  const bytes = decodeCanonicalBase64Url(value, context);
  if (bytes.byteLength !== length) {
    throw new ContractValidationError(`${context} must decode to ${length} bytes`);
  }
  return bytes;
}

export function encodeDeviceLink(link: DeviceLink): string {
  const bytes = new Uint8Array(DEVICE_LINK_BYTE_LENGTH);
  bytes.set(MAGIC_BYTES, 0);
  bytes[4] = DEVICE_LINK_VERSION;
  bytes.set(decodeExact(link.deviceLocator, 16, "device link locator"), 5);
  bytes.set(decodeExact(link.manageToken, 32, "device link management token"), 21);
  return encodeBase64Url(bytes);
}

export function decodeDeviceLink(fragment: string): DeviceLink {
  const bytes = decodeExact(fragment, DEVICE_LINK_BYTE_LENGTH, "device link");
  for (let index = 0; index < MAGIC_BYTES.byteLength; index += 1) {
    if (bytes[index] !== MAGIC_BYTES[index]) {
      throw new ContractValidationError("device link has an unknown magic");
    }
  }
  if (bytes[4] !== DEVICE_LINK_VERSION) {
    throw new ContractValidationError("device link has an unsupported version");
  }
  return {
    deviceLocator: encodeBase64Url(bytes.subarray(5, 21)),
    manageToken: encodeBase64Url(bytes.subarray(21, 53))
  };
}
