import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { checkProjectPath, projectPath, projectRoot, type PathRules } from "./project.js";

const root = realpathSync(mkdtempSync(join(tmpdir(), "kryptex-project-")));
execFileSync("git", ["init", "-q"], { cwd: root });
writeFileSync(join(root, ".gitignore"), "*.env\nsecrets/\nlinked/\n");
writeFileSync(join(root, "tracked.env"), "A=1\n");
execFileSync("git", ["add", "-f", "tracked.env"], { cwd: root });
mkdirSync(join(root, "secrets"));
mkdirSync(join(root, "sub"));
symlinkSync(join(root, "secrets"), join(root, "linked"));
writeFileSync(join(root, "secrets", "real.env"), "");
symlinkSync(join(root, "secrets", "real.env"), join(root, "pointer.env"));

afterAll(() => {
  rmSync(root, { force: true, recursive: true });
});

const output: PathRules = { existence: "either", output: true };
function expectInvalid(action: () => unknown): void {
  expect(action).toThrow(expect.objectContaining({ code: "target_invalid" }));
}

describe("project paths", () => {
  it("finds the project root from a subdirectory and resolves paths against the creation directory", () => {
    expect(projectRoot(join(root, "sub"))).toBe(root);
    expect(projectPath(root, join(root, "sub"), "../secrets/out.env")).toBe(join("secrets", "out.env"));
  });

  it("rejects paths outside the project", () => {
    expectInvalid(() => projectPath(root, root, "../outside.env"));
    expectInvalid(() => projectPath(root, root, "/etc/passwd"));
    expectInvalid(() => projectPath(root, root, "."));
  });

  it("accepts an ignored, untracked output", () => {
    expect(checkProjectPath(root, "new.env", output)).toBe(join(root, "new.env"));
    expect(checkProjectPath(root, join("secrets", "handoff.txt"), { existence: "absent", output: true })).toBe(join(root, "secrets", "handoff.txt"));
  });

  it("rejects outputs Git would track or commit", () => {
    expectInvalid(() => checkProjectPath(root, "tracked.env", output));
    expectInvalid(() => checkProjectPath(root, "visible.txt", output));
  });

  it("rejects symbolic links anywhere on the path", () => {
    expectInvalid(() => checkProjectPath(root, join("linked", "out.env"), output));
    expectInvalid(() => checkProjectPath(root, "pointer.env", output));
    expectInvalid(() => checkProjectPath(root, "pointer.env", { existence: "required", output: false }));
  });

  it("enforces the expected existence", () => {
    expectInvalid(() => checkProjectPath(root, join("secrets", "real.env"), { existence: "absent", output: true }));
    expectInvalid(() => checkProjectPath(root, "missing.env", { existence: "required", output: false }));
  });
});
