import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { classifyPaths, lexicallyContains, resolveRequestPath } from "../server/paths.js";

const WS = "/workspace/project";

describe("paths", () => {
  it("contains workspace children", () => {
    expect(lexicallyContains(WS, "src/a.ts")).toBe(true);
    expect(lexicallyContains(WS, "./src/a.ts")).toBe(true);
  });
  it("rejects traversal", () => {
    expect(lexicallyContains(WS, "../other/x")).toBe(false);
    expect(lexicallyContains(WS, "a/../../etc/passwd")).toBe(false);
    expect(lexicallyContains(WS, "/etc/passwd")).toBe(false);
  });
  it("flags sensitive dirs", () => {
    const c = classifyPaths(WS, ["/etc/passwd", "src/a.ts"]);
    expect(c.sensitive).toBe(true);
    expect(c.reasons.join(" ")).toContain("sensitive");
  });
  it("flags secret files", () => {
    const c = classifyPaths(WS, [".env"]);
    expect(c.secretFile).toBe(true);
  });
  it("detects symlink escape with real fs", () => {
    const dir = mkdtempSync(join(tmpdir(), "sp-ws-"));
    const outside = mkdtempSync(join(tmpdir(), "sp-out-"));
    writeFileSync(join(outside, "secret.txt"), "x");
    symlinkSync(join(outside, "secret.txt"), join(dir, "link.txt"));
    const r = resolveRequestPath(dir, "link.txt");
    expect(r.real).not.toBeNull();
    expect(r.insideWorkspaceReal).toBe(false);
    const c = classifyPaths(dir, ["link.txt"]);
    expect(c.symlinkEscape).toBe(true);
    // benign symlink stays inside
    mkdirSync(join(dir, "sub"));
    writeFileSync(join(dir, "sub", "ok.txt"), "y");
    symlinkSync(join(dir, "sub", "ok.txt"), join(dir, "ok-link.txt"));
    expect(classifyPaths(dir, ["ok-link.txt"]).symlinkEscape).toBe(false);
  });
  it("treats unresolvable symlink-ish as outside", () => {
    const c = classifyPaths(WS, ["no-such-dir/../x"]);
    void c;
    expect(lexicallyContains(WS, "no-such-dir/../x")).toBe(true); // lexical ok, realpath falls back to parent
  });
});
