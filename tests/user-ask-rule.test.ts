import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { DecisionCache } from "../server/cache.js";
import { DecisionEngine } from "../server/engine.js";
import { DisabledLayaClient, type LayaClient, type LayaVerdict } from "../server/laya.js";
import { LearnedStore, type UserRule } from "../server/rules.js";
import { validateUserRules } from "../shared/config.js";
import { SmartPermissionsService } from "../server/service.js";
import { agent, shell } from "./helpers.js";

function engine(opts: { userRules?: UserRule[]; laya?: LayaClient } = {}) {
  return new DecisionEngine({
    userRules: opts.userRules ?? [],
    learned: new LearnedStore(),
    laya: opts.laya ?? new DisabledLayaClient(),
    cache: new DecisionCache(60000),
    rulesVersion: 1,
    learningEnabled: true,
    defaultPolicy: "ask",
    maxConcurrency: 4,
    minConfidence: 0.6,
  });
}
const okAdvisor = (verdict: LayaVerdict): LayaClient & { calls: number } => {
  const stub = {
    name: "jev.openrouter",
    calls: 0,
    decide: async () => {
      stub.calls += 1;
      return { status: "ok", verdict } as const;
    },
  };
  return stub;
};

describe("ask rules: schema", () => {
  it("accepts effect=ask, still rejects unknown effects", () => {
    const { rules, issues } = validateUserRules([
      { id: "a", effect: "ask", commandPattern: "npm publish" },
    ]);
    expect(issues).toEqual([]);
    expect(rules).toEqual([{ id: "a", effect: "ask", commandPattern: "npm publish" }]);
    expect(validateUserRules([{ id: "bad", effect: "maybe" }]).issues).toHaveLength(1);
  });
});

describe("ask rules: engine priority deny > ask > allow", () => {
  it("ask forces human review (USER_RULE), advisor never consulted", async () => {
    const advisor = okAdvisor({ decision: "ALLOW", confidence: 0.99, reason: "sure", risk: "LOW" });
    const e = engine({
      userRules: [{ id: "u-ask", effect: "ask", commandPattern: "npm publish" }],
      laya: advisor,
    });
    const d = await e.decide(buildIR({ request: shell("npm publish"), agent: agent() }));
    expect(d).toMatchObject({ decision: "ASK", source: "USER_RULE" });
    expect(d.matchedRules).toContain("u-ask");
    expect(advisor.calls).toBe(0);
  });
  it("ask beats allow on the same request", async () => {
    const e = engine({
      userRules: [
        { id: "u-allow", effect: "allow", commandPattern: "npm" },
        { id: "u-ask", effect: "ask", commandPattern: "npm publish" },
      ],
    });
    const d = await e.decide(buildIR({ request: shell("npm publish"), agent: agent() }));
    expect(d).toMatchObject({ decision: "ASK", source: "USER_RULE" });
  });
  it("deny still beats ask", async () => {
    const e = engine({
      userRules: [
        { id: "u-ask", effect: "ask", commandPattern: "npm" },
        { id: "u-deny", effect: "deny", commandPattern: "npm publish" },
      ],
    });
    const d = await e.decide(buildIR({ request: shell("npm publish"), agent: agent() }));
    expect(d).toMatchObject({ decision: "DENY", source: "USER_RULE" });
  });
  it("non-matching ask rule lets allow through", async () => {
    const e = engine({
      userRules: [
        { id: "u-ask", effect: "ask", commandPattern: "npm publish" },
        { id: "u-allow", effect: "allow", commandPattern: "npm test" },
      ],
    });
    const d = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(d).toMatchObject({ decision: "ALLOW", source: "USER_RULE" });
  });
});

describe("ask rules: service wiring (ASK leaves native UI pending)", () => {
  it("ask rule from settings -> ASK with no respond call", async () => {
    const s = new SmartPermissionsService({ layaEnabled: false, jevEnabled: false });
    expect(s.applySettings({ ...s.settings, userRules: [
      { id: "u1", effect: "ask", commandPattern: "npm publish" },
    ] })).toBeNull();
    const calls: unknown[] = [];
    const out = await s.onPermissionRequested(
      shell("npm publish", "opencode"), agent("/workspace/project", "opencode"),
      async (...args) => { calls.push(args); },
    );
    expect(out.decision).toMatchObject({ decision: "ASK", source: "USER_RULE" });
    expect(out.responded).toBe(false);
    expect(calls).toHaveLength(0);
  });
});

describe("selective ask over the new shell baseline (user workflow)", () => {
  it("npm test auto-allows with a confident advisor while npm publish asks", async () => {
    const advisor = okAdvisor({ decision: "ALLOW", confidence: 0.9, reason: "sure", risk: "LOW" });
    const e = engine({
      userRules: [{ id: "u-publish", effect: "ask", commandPattern: "npm publish" }],
      laya: advisor,
    });
    const t = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(t).toMatchObject({ decision: "ALLOW", source: "LAYA" });
    const p = await e.decide(buildIR({ request: shell("npm publish"), agent: agent() }));
    expect(p).toMatchObject({ decision: "ASK", source: "USER_RULE" });
    expect(p.matchedRules).toContain("u-publish");
  });
});
