import { describe, expect, it } from "vitest";
import {
  advisorDisplayName,
  advisorDisplayNameFromRaw,
  advisorTag,
  type LayaClient,
  type LayaVerdict,
} from "../server/laya.js";
import { CompositeAdvisoryClient } from "../server/advisors.js";
import { DecisionCache } from "../server/cache.js";
import { DecisionEngine } from "../server/engine.js";
import { buildIR } from "../server/ir.js";
import { LearnedStore } from "../server/rules.js";
import { SmartPermissionsService } from "../server/service.js";
import { shell } from "./helpers.js";
import { agent } from "./helpers.js";

function engineFor(client: LayaClient) {
  return new DecisionEngine({
    userRules: [],
    learned: new LearnedStore(),
    laya: client,
    cache: new DecisionCache(60000),
    rulesVersion: 1,
    learningEnabled: false,
    defaultPolicy: "ask",
    maxConcurrency: 4,
    minConfidence: 0.6,
  });
}
const ok = (name: string, verdict: LayaVerdict): LayaClient => ({
  name,
  decide: async () => ({ status: "ok", verdict }),
});
const fail = (name: string): LayaClient => ({
  name,
  decide: async () => ({ status: "failed", kind: "network", detail: "down" }),
});

describe("advisor naming", () => {
  it("maps raw client names to display names", () => {
    expect(advisorDisplayNameFromRaw("jev.openrouter")).toBe("Jev");
    expect(advisorDisplayNameFromRaw("laya.http")).toBe("Laya");
    expect(advisorDisplayNameFromRaw("advisory.composite")).toBe("Jev+Laya");
  });
  it("composite of jev+laya displays as Jev+Laya with advisory tag", () => {
    const c = new CompositeAdvisoryClient([
      ok("jev.openrouter", { decision: "ASK", confidence: 0.9, reason: "j", risk: "MEDIUM" }),
      ok("laya.http", { decision: "ASK", confidence: 0.9, reason: "l", risk: "MEDIUM" }),
    ]);
    expect(advisorDisplayName(c)).toBe("Jev+Laya");
    expect(advisorTag(c)).toBe("advisory");
  });
  it("unknown stubs keep historic laya tag (no test churn)", () => {
    expect(advisorTag({ name: "stub", decide: async () => ({ status: "failed", kind: "network", detail: "x" }) })).toBe("laya");
  });
});

describe("engine attributes to the advisor that ran", () => {
  it("jev ASK defers as Jev, never Laya", async () => {
    const e = engineFor(ok("jev.openrouter", {
      decision: "ASK", confidence: 0.95,
      reason: "jev ask conf=0.95 risk=MEDIUM score=0.94 dangerous=0.53 inject=0.05",
      risk: "MEDIUM",
    }));
    const d = await e.decide(buildIR({ request: shell("echo hi"), agent: agent() }));
    expect(d.decision).toBe("ASK");
    expect(d.reason).toContain("Jev defers to human review");
    expect(d.reason).not.toContain("Laya");
    expect(d.matchedRules).toContain("jev");
    expect(d.matchedRules).not.toContain("laya");
  });
  it("jev low-confidence ALLOW names Jev with confidence gate", async () => {
    const e = engineFor(ok("jev.openrouter", {
      decision: "ALLOW", confidence: 0.41, reason: "jev allow conf=0.41", risk: "MEDIUM",
    }));
    const d = await e.decide(buildIR({ request: shell("echo hi"), agent: agent() }));
    expect(d.decision).toBe("ASK");
    expect(d.reason).toContain("Jev verdict ALLOW has confidence 0.41 < 0.6");
    expect(d.reason).not.toContain("Laya");
  });
  it("laya verdicts still name Laya", async () => {
    const e = engineFor(ok("laya.http", {
      decision: "ASK", confidence: 0.9, reason: "local model unsure", risk: "MEDIUM",
    }));
    const d = await e.decide(buildIR({ request: shell("echo hi"), agent: agent() }));
    expect(d.reason).toContain("Laya defers to human review");
    expect(d.matchedRules).toContain("laya");
  });
  it("jev outage names Jev, not Laya", async () => {
    const e = engineFor(fail("jev.openrouter"));
    const d = await e.decide(buildIR({ request: shell("echo hi"), agent: agent() }));
    expect(d.reason).toContain("Jev unavailable");
    expect(d.reason).not.toContain("Laya");
  });
});

describe("service stats exposes friendly advisor", () => {
  it("jev-only service reports advisor=Jev", () => {
    const s = new SmartPermissionsService({ jevEnabled: true, jevApiKey: "k", layaEnabled: false });
    expect(s.stats().advisor).toBe("Jev");
    expect(s.stats().laya).toBe("jev.openrouter");
  });
  it("composite reports Jev+Laya", () => {
    const s = new SmartPermissionsService({ jevEnabled: true, jevApiKey: "k", layaEnabled: true });
    expect(s.stats().advisor).toBe("Jev+Laya");
  });
});
