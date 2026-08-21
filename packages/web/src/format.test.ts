import { describe, expect, it } from "vitest";
import { VALUE_FIELD_TYPES, describeRequestState, describeSendState, formatFieldType, formatOpenAllowance, formatOpens, formatTimeLeft, formatTtl, isMultilineField, isSensitiveField, isValueFieldType } from "./format";

describe("human-readable protocol state", () => {
  it("names every send and request state without exposing wire values", () => {
    expect(describeSendState("active").label).toBe("Active");
    expect(describeSendState("exhausted").label).toBe("All opens used");
    expect(describeSendState("revoked").tone).toBe("danger");
    expect(describeSendState("expired").label).toBe("Expired");
    expect(describeRequestState("picked_up").label).toBe("Answer opened");
    expect(describeRequestState("submitted").label).toBe("Answer ready");
    expect(describeRequestState("waiting").label).toBe("Waiting for an answer");
  });

  it("keeps time left coarse and never counts past expiry", () => {
    expect(formatTimeLeft(1_000, 1_000)).toBe("already passed");
    expect(formatTimeLeft(900, 1_000)).toBe("already passed");
    expect(formatTimeLeft(1_030, 1_000)).toBe("in under a minute");
    expect(formatTimeLeft(1_060, 1_000)).toBe("in 1 minute");
    expect(formatTimeLeft(4_599, 1_000)).toBe("in 59 minutes");
    expect(formatTimeLeft(4_600, 1_000)).toBe("in 1 hour");
    expect(formatTimeLeft(605_800, 1_000)).toBe("in 7 days");
  });

  it("counts releases in plain words", () => {
    expect(formatOpens(0)).toBe("no opens left");
    expect(formatOpens(1)).toBe("1 open left");
    expect(formatOpens(4)).toBe("4 opens left");
    expect(formatOpenAllowance(1)).toBe("can be opened once");
    expect(formatOpenAllowance(2)).toBe("can be opened twice");
    expect(formatOpenAllowance(5)).toBe("can be opened 5 times");
    expect(formatTtl(28_800)).toBe("8 hours");
  });
});

describe("shared value-type vocabulary", () => {
  it("offers the same four value types to send and request composers", () => {
    expect(VALUE_FIELD_TYPES).toEqual(["secret", "text", "long-secret", "long-text"]);
    expect(VALUE_FIELD_TYPES.map(formatFieldType)).toEqual(["Secret", "Plain text", "Long secret — multi-line", "Long text — multi-line"]);
    expect(formatFieldType("instruction")).toBe("Instruction — label only");
  });

  it("derives entry shape and sensitivity from the type alone", () => {
    expect(VALUE_FIELD_TYPES.filter(isSensitiveField)).toEqual(["secret", "long-secret"]);
    expect(VALUE_FIELD_TYPES.filter(isMultilineField)).toEqual(["long-secret", "long-text"]);
    expect(isSensitiveField("instruction")).toBe(false);
    expect(isMultilineField("instruction")).toBe(false);
  });

  it("rejects a request-only type where only a value type is allowed", () => {
    expect(VALUE_FIELD_TYPES.every(isValueFieldType)).toBe(true);
    expect(isValueFieldType("instruction")).toBe(false);
    expect(isValueFieldType("long")).toBe(false);
  });
});
