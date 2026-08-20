import { describe, expect, it } from "vitest";

import { canonicalSecretRoute, captureAndScrubFragment, isSecretRoute } from "./fragment";

describe("fragment lifecycle", () => {
  it("captures fragment presence and replaces the visible URL synchronously", () => {
    let replacement = "";
    const capture = captureAndScrubFragment(
      { hash: "#secret-bundle", pathname: "/s", search: "?language=en" },
      {
        state: { navigation: 1 },
        replaceState(_data, _unused, url) {
          replacement = String(url);
        }
      }
    );

    expect(capture.hadFragment).toBe(true);
    expect(capture.canonicalPathname).toBe("/s");
    expect(capture.fragmentBytes === null ? null : new TextDecoder().decode(capture.fragmentBytes)).toBe("secret-bundle");
    expect(replacement).toBe("/s");
  });

  it("does not expose the copied value in the result", () => {
    const capture = captureAndScrubFragment(
      { hash: "#must-not-escape", pathname: "/i", search: "" },
      {
        state: null,
        replaceState() {
          return undefined;
        }
      }
    );

    expect(capture.fragmentBytes === null ? null : new TextDecoder().decode(capture.fragmentBytes)).toBe("must-not-escape");
  });

  it("accepts exact and one-trailing-slash capability routes", () => {
    expect(isSecretRoute("/s")).toBe(true);
    expect(isSecretRoute("/s/")).toBe(true);
    expect(isSecretRoute("/m")).toBe(true);
    expect(isSecretRoute("/m/")).toBe(true);
    expect(isSecretRoute("/r")).toBe(true);
    expect(isSecretRoute("/r/")).toBe(true);
    expect(isSecretRoute("/i")).toBe(true);
    expect(isSecretRoute("/i/")).toBe(true);
    expect(canonicalSecretRoute("/s/")).toBe("/s");
  });

  it("rejects lookalike and nested routes", () => {
    expect(isSecretRoute("/send")).toBe(false);
    expect(isSecretRoute("/security")).toBe(false);
    expect(isSecretRoute("/s//")).toBe(false);
    expect(isSecretRoute("/s/nested")).toBe(false);
  });

  it("canonicalizes a trailing slash and drops query and fragment before rendering", () => {
    let replacement = "";
    const capture = captureAndScrubFragment(
      { hash: "#bundle", pathname: "/r/", search: "?language=cs&mode=preview" },
      {
        state: null,
        replaceState(_data, _unused, url) {
          replacement = String(url);
        }
      }
    );

    expect(capture.canonicalPathname).toBe("/r");
    expect(replacement).toBe("/r");
  });
});
