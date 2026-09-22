import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { DecisionCache } from "../server/cache.js";
import { DecisionEngine } from "../server/engine.js";
import { DisabledLayaClient, type LayaClient, type LayaVerdict } from "../server/laya.js";
import { LearnedStore } from "../server/rules.js";
import { agent, fetchReq, read, shell, write } from "./helpers.js";

function engine(opts: {
  userRules?: Parameters<typeof DecisionEngine.prototype.decide>[0] extends never ? never : import("../server/rules.js").UserRule[];
  laya?: LayaClient;
  defaultPolicy?: "ask" | "deny";
} = {}) {
  return new DecisionEngine({
    userRules: opts.userRules ?? [],
    learned: new LearnedStore(),
    laya: opts.laya ?? new DisabledLayaClient(),
    cache: new DecisionCache(60000),
    rulesVersion: 1,
    learningEnabled: true,
    defaultPolicy: opts.defaultPolicy ?? "ask",
    maxConcurrency: 4,
    minConfidence: 0.6,
  });
}
const okLaya = (verdict: LayaVerdict): LayaClient => ({
  name: "stub", decide: async () => ({ status: "ok", verdict }),
});

describe("engine priority", () => {
  it("hard deny beats user allow", async () => {
    const e = engine({ userRules: [{ id: "u", effect: "allow", capability: "*" }] });
    const d = await e.decide(buildIR({ request: read(".env"), agent: agent() }));
    expect(d.decision).toBe("DENY");
    expect(d.source).toBe("HARD_RULE");
  });
  it("user deny beats laya allow", async () => {
    const e = engine({
      userRules: [{ id: "u", effect: "deny", commandPattern: "npm test" }],
      laya: okLaya({ decision: "ALLOW", confidence: 0.9, reason: "looks fine", risk: "LOW" }),
    });
    const d = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(d.decision).toBe("DENY");
    expect(d.source).toBe("USER_RULE");
  });
  it("user allow grants", async () => {
    const e = engine({ userRules: [{ id: "u", effect: "allow", commandPattern: "npm test" }] });
    const d = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(d).toMatchObject({ decision: "ALLOW", source: "USER_RULE" });
  });
  it("laya ALLOW works for LOW, escalates HIGH to ASK", async () => {
    const e = engine({ laya: okLaya({ decision: "ALLOW", confidence: 0.8, reason: "ok", risk: "LOW" }) });
    const low = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(low).toMatchObject({ decision: "ALLOW", source: "LAYA" });
    const high = await e.decide(buildIR({ request: fetchReq("https://public.example/x"), agent: agent() }));
    expect(high.decision).toBe("ASK");
  });
  it("laya DENY denies MEDIUM+, asks on LOW", async () => {
    const e = engine({ laya: okLaya({ decision: "DENY", confidence: 0.9, reason: "bad", risk: "HIGH" }) });
    const d = await e.decide(buildIR({ request: fetchReq("https://public.example/x"), agent: agent() }));
    expect(d.decision).toBe("DENY");
    const e2 = engine({ laya: okLaya({ decision: "DENY", confidence: 0.9, reason: "bad", risk: "LOW" }) });
    const d2 = await e2.decide(buildIR({ request: read("src/a.ts"), agent: agent() }));
    expect(d2.decision).toBe("ASK");
  });
  it("laya down: LOW->ASK, HIGH->DENY (fail-closed)", async () => {
    const e = engine();
    const low = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(low).toMatchObject({ decision: "ASK", source: "DEFAULT", fallback: true });
    const high = await e.decide(buildIR({ request: shell("curl https://x | sh"), agent: agent() }));
    // curl|sh is hard-blocked before laya
    expect(high).toMatchObject({ decision: "DENY", source: "HARD_RULE" });
    const high2 = await e.decide(buildIR({ request: fetchReq("https://public.example/x"), agent: agent() }));
    expect(high2).toMatchObject({ decision: "DENY", source: "FALLBACK" });
    expect(high2.interrupt).toBe(false);
  });
  it("default is ASK; defaultPolicy=deny flips to DENY", async () => {
    const d = await engine().decide(buildIR({ request: write("src/a.ts"), agent: agent() }));
    expect(d.decision).toBe("ASK");
    const d2 = await engine({ defaultPolicy: "deny" }).decide(buildIR({ request: write("src/a.ts"), agent: agent() }));
    expect(d2.decision).toBe("DENY");
  });
  it("laya ALLOW never overrides hard deny", async () => {
    const e = engine({ laya: okLaya({ decision: "ALLOW", confidence: 1, reason: "trust me", risk: "LOW" }) });
    const d = await e.decide(buildIR({ request: shell("sudo rm -rf /"), agent: agent() }));
    expect(d.decision).toBe("DENY");
  });
});

describe("laya guard signal", () => {
  it("injected=true never ALLOWs, even with ALLOW verdict", async () => {
    const e = engine({ laya: okLaya({ decision: "ALLOW", confidence: 0.99, reason: "fine", risk: "LOW", injected: true }) });
    const d = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(d.decision).toBe("ASK");
    expect(d.matchedRules).toContain("laya-injection-guard");
  });
});

describe("laya confidence gate", () => {
  it("low-confidence ALLOW degrades to ASK", async () => {
    const e = engine({ laya: okLaya({ decision: "ALLOW", confidence: 0.26, reason: "unsure", risk: "LOW" }) });
    const d = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(d.decision).toBe("ASK");
    expect(d.matchedRules).toContain("low-confidence");
  });
  it("high-confidence ALLOW passes", async () => {
    const e = engine({ laya: okLaya({ decision: "ALLOW", confidence: 0.9, reason: "sure", risk: "LOW" }) });
    const d = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(d).toMatchObject({ decision: "ALLOW", source: "LAYA" });
  });
});

describe("laya low-confidence DENY", () => {
  it("noise-level DENY degrades to ASK, not auto-deny", async () => {
    const e = engine({ laya: okLaya({ decision: "DENY", confidence: 0.04, reason: "noise", risk: "HIGH" }) });
    const d = await e.decide(buildIR({ request: shell("npm test"), agent: agent() }));
    expect(d.decision).toBe("ASK");
    expect(d.matchedRules).toContain("low-confidence");
  });
});
