import { afterEach, describe, expect, test, vi } from "vitest";
import { randomBytes } from "./bytes.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("random bytes", () => {
  test("fills large buffers without exceeding the Web Crypto per-call quota", () => {
    const calls: number[] = [];
    vi.spyOn(crypto, "getRandomValues").mockImplementation((array) => {
      calls.push(array.byteLength);
      return array;
    });

    expect(randomBytes(262_145)).toHaveLength(262_145);
    expect(calls).toEqual([65_536, 65_536, 65_536, 65_536, 1]);
  });
});
