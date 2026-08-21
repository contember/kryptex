export const CIPHERTEXT_BUCKET_NAME = "kryptex-ciphertext";
export const CANDIDATE_PREFIX = "v1/candidates/";
export const CANDIDATE_RULE_ID = "kryptex-v1-candidate-backstop";
export const CANDIDATE_MAX_AGE_DAYS = 31;
export const CANDIDATE_MAX_AGE_SECONDS = CANDIDATE_MAX_AGE_DAYS * 24 * 60 * 60;

export const EXPECTED_CANDIDATE_RULE = Object.freeze({
  id: CANDIDATE_RULE_ID,
  enabled: true,
  conditions: {
    prefix: CANDIDATE_PREFIX
  },
  deleteObjectsTransition: {
    condition: {
      type: "Age",
      maxAge: CANDIDATE_MAX_AGE_SECONDS
    }
  }
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ruleId(rule: unknown): string | undefined {
  return isRecord(rule) && typeof rule["id"] === "string" ? rule["id"] : undefined;
}

function rulePrefix(rule: Record<string, unknown>): string | undefined {
  if (!isRecord(rule["conditions"])) {
    return undefined;
  }
  return typeof rule["conditions"]["prefix"] === "string" ? rule["conditions"]["prefix"] : undefined;
}

function hasDeleteTransition(rule: Record<string, unknown>): boolean {
  return "deleteObjectsTransition" in rule && rule["deleteObjectsTransition"] !== null;
}

function prefixesOverlap(first: string, second: string): boolean {
  return first.startsWith(second) || second.startsWith(first);
}

function isExpectedRule(rule: unknown): boolean {
  if (!isRecord(rule) || rule["id"] !== CANDIDATE_RULE_ID || rule["enabled"] !== true) {
    return false;
  }
  if (rulePrefix(rule) !== CANDIDATE_PREFIX || !isRecord(rule["deleteObjectsTransition"])) {
    return false;
  }
  const transition = rule["deleteObjectsTransition"];
  return isRecord(transition["condition"])
    && transition["condition"]["type"] === "Age"
    && transition["condition"]["maxAge"] === CANDIDATE_MAX_AGE_SECONDS;
}

function assertNoConflictingDeleteRules(rules: readonly unknown[]): void {
  for (const rule of rules) {
    if (!isRecord(rule) || ruleId(rule) === CANDIDATE_RULE_ID || rule["enabled"] === false || !hasDeleteTransition(rule)) {
      continue;
    }
    const prefix = rulePrefix(rule);
    if (prefix === undefined) {
      throw new Error("An enabled R2 delete rule has no readable prefix");
    }
    if (prefixesOverlap(prefix, CANDIDATE_PREFIX)) {
      throw new Error(`R2 delete rule ${ruleId(rule) ?? "<unknown>"} overlaps ${CANDIDATE_PREFIX}`);
    }
  }
}

export interface LifecycleReconciliation {
  readonly changed: boolean;
  readonly rules: readonly unknown[];
}

export function reconcileLifecycleRules(rules: readonly unknown[]): LifecycleReconciliation {
  assertNoConflictingDeleteRules(rules);
  const matchingRules = rules.filter((rule) => ruleId(rule) === CANDIDATE_RULE_ID);
  if (matchingRules.length === 1 && isExpectedRule(matchingRules[0])) {
    return { changed: false, rules };
  }
  return {
    changed: true,
    rules: [
      ...rules.filter((rule) => ruleId(rule) !== CANDIDATE_RULE_ID),
      EXPECTED_CANDIDATE_RULE
    ]
  };
}

export function verifyLifecycleRules(rules: readonly unknown[]): void {
  assertNoConflictingDeleteRules(rules);
  const matchingRules = rules.filter((rule) => ruleId(rule) === CANDIDATE_RULE_ID);
  if (matchingRules.length !== 1 || !isExpectedRule(matchingRules[0])) {
    throw new Error(`R2 lifecycle rule ${CANDIDATE_RULE_ID} does not match the required 31-day policy`);
  }
}
