import { describe, expect, it } from "vitest";
import { SETTINGS_ID, defaultSettings } from "../shared/config.js";
import { applySettingsDraft, ruleHasCondition } from "../shared/settings-def.js";
import { SmartPermissionsService } from "../server/service.js";
import { agent, shell } from "./helpers.js";

describe("applySettingsDraft", () => {
  it("applies strings, toggles, numerics, policy", () => {
    const next = applySettingsDraft(defaultSettings(), {
      jevApiKey: "k", jevModel: "typesafe/jev-1.13", jevEndpoint: "https://x/decide",
      jevTimeoutMs: "8000", jevMinConfidence: "0.8", defaultPolicy: "deny",
    }, { enabled: false, jevEnabled: true });
    expect(next.jevApiKey).toBe("k");
    expect(next.jevTimeoutMs).toBe(8000);
    expect(next.jevMinConfidence).toBeCloseTo(0.8);
    expect(next.defaultPolicy).toBe("deny");
    expect(next.enabled).toBe(false);
    expect(next.jevEnabled).toBe(true);
  });
  it("invalid numerics/policy fall back to base (never NaN)", () => {
    const base = defaultSettings();
    const next = applySettingsDraft(base, {
      jevTimeoutMs: "soon", jevMinConfidence: "lots", defaultPolicy: "maybe",
    }, {});
    expect(next.jevTimeoutMs).toBe(base.jevTimeoutMs);
    expect(next.jevMinConfidence).toBe(base.jevMinConfidence);
    expect(next.defaultPolicy).toBe(base.defaultPolicy);
  });
  it("out-of-range values are rejected by schema", () => {
    expect(() => applySettingsDraft(defaultSettings(), { jevTimeoutMs: "-5" }, {}))
      .toThrow();
  });
});

describe("cache TTL in seconds (v2)", () => {
  it("defaults to 60s and drafts seconds through", async () => {
    const { defaultSettings } = await import("../shared/config.js");
    const { applySettingsDraft, migrateSettings } = await import("../shared/settings-def.js");
    expect(defaultSettings().cacheTtlSec).toBe(60);
    expect(applySettingsDraft(defaultSettings(), { cacheTtlSec: "120" }, {}).cacheTtlSec).toBe(120);
  });
  it("migrates stored v1 milliseconds", async () => {
    const { migrateSettings } = await import("../shared/settings-def.js");
    expect(migrateSettings({ cacheTtlMs: 120000 })).toEqual({ cacheTtlSec: 120, language: "en" });
    expect(migrateSettings({ cacheTtlMs: 1500 })).toEqual({ cacheTtlSec: 2, language: "en" });
    expect(migrateSettings({ cacheTtlSec: 30, cacheTtlMs: 120000 })).toEqual({ cacheTtlSec: 30, language: "en" });
    expect(migrateSettings({ language: "zh", cacheTtlMs: 120000 })).toEqual({ language: "zh", cacheTtlSec: 120 });
    expect(migrateSettings(null)).toEqual({});
  });
});

describe("settings registration", () => {
  it("SETTINGS_ID satisfies the SDK constraint (/^[a-z][a-z0-9_-]*$/)", () => {
    expect(SETTINGS_ID).toMatch(/^[a-z][a-z0-9_-]*$/);
  });
});

describe("applySettingsDraft user rules", () => {
  const rule = { id: "u1", effect: "allow" as const, commandPattern: "npm test" };
  it("valid rules are applied", () => {
    const next = applySettingsDraft(defaultSettings(), {}, {}, [rule]);
    expect(next.userRules).toEqual([rule]);
  });
  it("invalid rule rejects the whole save with indexed detail", () => {
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      rule,
      { id: "bad", effect: "maybe" },
    ])).toThrow(/rule #2/);
  });
  it("rules omitted -> base rules preserved", () => {
    const base = { ...defaultSettings(), userRules: [rule] };
    expect(applySettingsDraft(base, {}, {}).userRules).toEqual([rule]);
  });
  it("empty array clears rules", () => {
    const base = { ...defaultSettings(), userRules: [rule] };
    expect(applySettingsDraft(base, {}, {}, []).userRules).toEqual([]);
  });
  it("commandPattern with * is rejected with a fix hint (literal, not wildcard)", () => {
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", commandPattern: "kubectl get *" },
    ])).toThrow(/literally.*substring "kubectl get"/);
  });
  it("invalid /regex/ commandPattern is rejected instead of crashing the engine", () => {
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", commandPattern: "/([a/" },
    ])).toThrow(/invalid regex/);
    const next = applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", commandPattern: "/kubectl get.*/" },
    ]);
    expect(next.userRules).toHaveLength(1);
  });
  it("blank commandPattern is rejected (matches almost everything)", () => {
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", commandPattern: "   " },
    ])).toThrow(/blank pattern/);
  });
  it("provider/capability typos and case mistakes are rejected with hints", () => {
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", provider: "opencdoe", commandPattern: "npm test" },
    ])).toThrow(/provider: "opencdoe" never matches/);
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", provider: "OpenCode", commandPattern: "npm test" },
    ])).toThrow(/did you mean "opencode"/);
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", capability: "File.Read" },
    ])).toThrow(/did you mean "file.read"/);
  });
  it("relative/~ workspace and URL-like hostPattern are rejected", () => {
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", workspace: "project/foo" },
    ])).toThrow(/must be absolute/);
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", workspace: "~/project" },
    ])).toThrow(/never matches/);
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", hostPattern: "https://example.com/x" },
    ])).toThrow(/bare names/);
    const next = applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", workspace: "/w/project", hostPattern: "example.com" },
    ]);
    expect(next.userRules).toHaveLength(1);
  });
  it("blank/duplicate ids and condition-free allow/ask are rejected; deny-all stays legal", () => {
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "  ", effect: "allow", commandPattern: "npm test" },
    ])).toThrow(/id: must not be blank/);
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", commandPattern: "npm test" },
      { id: "u1", effect: "deny", commandPattern: "rm" },
    ])).toThrow(/duplicates rule #1/);
    // "*" is not a condition: allow-all / ask-everything blocked on every save path…
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "allow", provider: "*" },
    ])).toThrow(/need at least one match condition/);
    expect(() => applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "ask", capability: "*" },
    ])).toThrow(/need at least one match condition/);
    // …but unconditional deny is fail-closed and stays legal.
    const next = applySettingsDraft(defaultSettings(), {}, {}, [
      { id: "u1", effect: "deny" },
    ]);
    expect(next.userRules).toHaveLength(1);
  });
  it("service applySettings (RPC path) enforces the same validation", () => {
    const s = new SmartPermissionsService({ layaEnabled: false, jevEnabled: false });
    expect(s.applySettings({ ...s.settings, userRules: [
      { id: "u1", effect: "allow", commandPattern: "kubectl get *" },
    ] })).toMatch(/literally/);
    expect(s.applySettings({ ...s.settings, userRules: [
      { id: "u1", effect: "allow", provider: "opencode", commandPattern: "npm test" },
    ] })).toBeNull();
  });
  it("ruleHasCondition guards allow-all shape", () => {
    expect(ruleHasCondition({})).toBe(false);
    expect(ruleHasCondition({ commandPattern: "npm test" })).toBe(true);
    expect(ruleHasCondition({ workspace: "/w" })).toBe(true);
  });
});

describe("draft rules -> live engine (贯通)", () => {
  async function decideWith(rules: unknown[]) {
    const s = new SmartPermissionsService({ layaEnabled: false, jevEnabled: false });
    const draft = applySettingsDraft(s.settings, {}, {}, rules);
    const err = s.applySettings(draft as unknown as Record<string, unknown>);
    expect(err).toBeNull();
    const calls: unknown[] = [];
    const out = await s.onPermissionRequested(
      shell("npm test", "opencode"), agent("/workspace/project", "opencode"),
      async (...args) => { calls.push(args); },
    );
    return { ...out, calls };
  }
  it("allow rule from the editor flips ASK -> ALLOW", async () => {
    const { decision, calls } = await decideWith([
      { id: "u1", effect: "allow", provider: "opencode", commandPattern: "npm test" },
    ]);
    expect(decision).toMatchObject({ decision: "ALLOW", source: "USER_RULE" });
    expect(calls).toHaveLength(1);
  });
  it("deny rule from the editor wins over allow (deny-first)", async () => {
    const { decision } = await decideWith([
      { id: "u1", effect: "allow", provider: "opencode", commandPattern: "npm test" },
      { id: "u2", effect: "deny", provider: "opencode", commandPattern: "npm" },
    ]);
    expect(decision).toMatchObject({ decision: "DENY", source: "USER_RULE" });
  });
});
