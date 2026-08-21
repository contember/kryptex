import { describe, expect, test } from "vitest";
import {
  CANDIDATE_MAX_AGE_SECONDS,
  EXPECTED_CANDIDATE_RULE,
  reconcileLifecycleRules,
  verifyLifecycleRules
} from "./r2-policy.js";

describe("R2 lifecycle policy", () => {
  test("keeps an exact policy unchanged", () => {
    const rules = [{ id: "archive", enabled: false }, EXPECTED_CANDIDATE_RULE];
    expect(reconcileLifecycleRules(rules)).toEqual({ changed: false, rules });
    expect(() => {
      verifyLifecycleRules(rules);
    }).not.toThrow();
  });

  test("replaces duplicate or stale managed rules and preserves unrelated rules", () => {
    const unrelated = {
      id: "other-prefix",
      enabled: true,
      conditions: { prefix: "other/" },
      deleteObjectsTransition: { condition: { type: "Age", maxAge: 60 } }
    };
    const stale = {
      ...EXPECTED_CANDIDATE_RULE,
      deleteObjectsTransition: { condition: { type: "Age", maxAge: CANDIDATE_MAX_AGE_SECONDS - 1 } }
    };
    const result = reconcileLifecycleRules([stale, unrelated, stale]);
    expect(result.changed).toBe(true);
    expect(result.rules).toEqual([unrelated, EXPECTED_CANDIDATE_RULE]);
  });

  test.each(["", "v1/", "v1/candidates/expired/"])("rejects an overlapping delete prefix: %s", (prefix) => {
    const conflict = {
      id: "conflict",
      enabled: true,
      conditions: { prefix },
      deleteObjectsTransition: { condition: { type: "Age", maxAge: 60 } }
    };
    expect(() => reconcileLifecycleRules([conflict])).toThrow(/overlaps/u);
  });

  test("ignores disabled overlapping rules", () => {
    const disabled = {
      id: "disabled",
      enabled: false,
      conditions: { prefix: "v1/" },
      deleteObjectsTransition: { condition: { type: "Age", maxAge: 60 } }
    };
    expect(reconcileLifecycleRules([disabled]).rules).toEqual([disabled, EXPECTED_CANDIDATE_RULE]);
  });
});
