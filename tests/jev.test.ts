import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import {
  HttpJevClient, JEV_DEFAULT_ENDPOINT, JEV_DEFAULT_MODEL, JEV_QUESTIONS,
  buildJevState, jevAnswersToVerdict, jevScoreToRisk,
} from "../server/jev.js";
import { CompositeAdvisoryClient } from "../server/advisors.js";
import type { LayaOutcome } from "../server/laya.js";
import { SmartPermissionsService } from "../server/service.js";
import { agent, shell } from "./helpers.js";

const ir = () => buildIR({ request: shell("npm test"), agent: agent() });

function jevOk(body: unknown) {
  return (async () => new Response(JSON.stringify(body), { status: 200 })) as typeof fetch;
}
function answers(decision: string, score: number, opts: { conf?: number; inject?: number; dangerous?: number } = {}) {
  return {
    answers: {
      decision: { type: "choice", choice: decision, confidence: opts.conf ?? 0.9, probabilities: { [decision]: 0.9 } },
      is_dangerous: { type: "noul", noul: opts.dangerous ?? 0.1 },
      is_workspace_escape: { type: "noul", noul: 0.02 },
      is_secret_access: { type: "noul", noul: 0.05 },
      risk_level: { type: "score", score, legend: { 0: "low", 1: "medium", 2: "high", 3: "critical" }, confidence: 0.9 },
      prompt_injection: { type: "noul", noul: opts.inject ?? 0.03 },
    },
  };
}

describe("jev score mapping", () => {
  it("maps expected scores to risk bands", () => {
    expect(jevScoreToRisk(0.1)).toBe("LOW");
    expect(jevScoreToRisk(1.1)).toBe("MEDIUM");
    expect(jevScoreToRisk(2.0)).toBe("HIGH");
    expect(jevScoreToRisk(2.95)).toBe("CRITICAL");
    expect(jevScoreToRisk(Number.NaN)).toBe("HIGH"); // fail safe
  });
  it("converts answers to verdicts (deny/critical)", () => {
    const v = jevAnswersToVerdict(answers("deny", 2.95, { conf: 0.99 }).answers as never);
    expect(v).toMatchObject({ decision: "DENY", risk: "CRITICAL", injected: false });
    expect(v.confidence).toBeCloseTo(0.99);
  });
  it("flags prompt injection", () => {
    const v = jevAnswersToVerdict(answers("ask", 1.24, { conf: 0.4, inject: 0.98 }).answers as never);
    expect(v.injected).toBe(true);
  });
  it("rejects unknown choices", () => {
    expect(() => jevAnswersToVerdict(answers("maybe", 1.0).answers as never)).toThrow();
  });
});

describe("jev request (typed-decision contract)", () => {
  it("exposes the 6-question preset", () => {
    expect(Object.keys(JEV_QUESTIONS).sort()).toEqual(
      ["decision", "is_dangerous", "is_secret_access", "is_workspace_escape", "prompt_injection", "risk_level"].sort(),
    );
    expect(JEV_QUESTIONS.decision.type).toBe("choice");
    expect(JEV_QUESTIONS.risk_level.type).toBe("score");
  });
  it("state carries typed fields + untrusted policy, no prompt text", () => {
    const st = buildJevState(ir());
    expect(Object.keys(st).sort()).toEqual(
      ["action", "capability", "command", "deterministic_risk", "hosts", "paths", "policy", "risk_reasons", "tool", "untrusted", "workspace"].sort(),
    );
    expect(st.policy).toContain("attacker-controlled");
    expect("system" in st).toBe(false);
  });
  it("sanitizes raw command (no secrets cross the wire)", () => {
    const bad = buildIR({ request: shell("export TOKEN=sk-abcdefghijklmnop1234 && deploy"), agent: agent() });
    expect(JSON.stringify(buildJevState(bad))).not.toContain("abcdefghijklmnop");
  });
});

describe("HttpJevClient", () => {
  it("maps ok verdicts and posts model + bearer auth", async () => {
    let url = "";
    let body = "";
    let auth: string | null = null;
    const c = new HttpJevClient({
      apiKey: "k", timeoutMs: 3000,
      fetchImpl: (async (u: unknown, init: unknown) => {
        url = String(u);
        const h = (init as { headers: Record<string, string> }).headers;
        auth = h.authorization;
        body = String((init as { body: string }).body);
        return new Response(JSON.stringify(answers("deny", 2.95, { conf: 0.99 })), { status: 200 });
      }) as typeof fetch,
    });
    const out = await c.decide(ir());
    expect(url).toBe(JEV_DEFAULT_ENDPOINT);
    expect(auth).toBe("Bearer k");
    expect(JSON.parse(body).model).toBe(JEV_DEFAULT_MODEL);
    expect(out).toMatchObject({ status: "ok" });
    if (out.status === "ok") expect(out.verdict).toMatchObject({ decision: "DENY", risk: "CRITICAL" });
  });
  it("missing decision -> invalid failure", async () => {
    const c = new HttpJevClient({ apiKey: "k", timeoutMs: 3000, fetchImpl: jevOk({ answers: {} }) });
    expect(await c.decide(ir())).toMatchObject({ status: "failed", kind: "invalid" });
  });
  it("HTTP 401 -> http failure", async () => {
    const c = new HttpJevClient({
      apiKey: "bad", timeoutMs: 3000,
      fetchImpl: (async () => new Response("unauthorized", { status: 401 })) as typeof fetch,
    });
    expect(await c.decide(ir())).toMatchObject({ status: "failed", kind: "http" });
  });
  it("timeout maps to timeout failure", async () => {
    const c = new HttpJevClient({
      apiKey: "k", timeoutMs: 50,
      fetchImpl: (((_u: unknown, init: unknown) => new Promise((_res, rej) => {
        const signal = (init as { signal: AbortSignal }).signal;
        const onAbort = () => { const e = new Error("aborted"); e.name = "AbortError"; rej(e); };
        if (signal.aborted) { onAbort(); return; }
        signal.addEventListener("abort", onAbort, { once: true });
      })) as unknown) as typeof fetch,
    });
    expect(await c.decide(ir())).toMatchObject({ status: "failed", kind: "timeout" });
  });
  it("circuit opens after 5 failures", async () => {
    const c = new HttpJevClient({
      apiKey: "k", timeoutMs: 1000,
      fetchImpl: (async () => new Response("nope", { status: 500 })) as typeof fetch,
    });
    for (let i = 0; i < 5; i++) await c.decide(ir());
    expect(c.circuitOpen).toBe(true);
  });
});

describe("HttpJevClient endpoint compat", () => {
  const okBody = () => JSON.stringify({
    answers: {
      decision: { type: "choice", choice: "ask", confidence: 0.7 },
      risk_level: { type: "score", score: 1.0 },
    },
  });
  it("sends OpenRouter headers only to openrouter.ai", async () => {
    let headers: Record<string, string> = {};
    const c = new HttpJevClient({
      endpoint: "https://openrouter.ai/api/alpha/decisions", model: "typesafe/jev-1.13",
      apiKey: "k", timeoutMs: 3000,
      fetchImpl: (async (_u: unknown, init: unknown) => {
        headers = (init as { headers: Record<string, string> }).headers;
        return new Response(okBody(), { status: 200 });
      }) as typeof fetch,
    });
    await c.decide(ir());
    expect(headers["HTTP-Referer"]).toBeDefined();
    expect(headers["X-Title"]).toBeDefined();
  });
  it("custom endpoint gets no OpenRouter headers (self-hosted safe)", async () => {
    let headers: Record<string, string> = {};
    let capturedUrl = "";
    let capturedBody = "";
    const c = new HttpJevClient({
      endpoint: "https://jev.internal.example.com/decide", model: "custom-jev",
      apiKey: "k", timeoutMs: 3000,
      fetchImpl: (async (u: unknown, init: unknown) => {
        headers = (init as { headers: Record<string, string> }).headers;
        capturedUrl = String(u);
        capturedBody = String((init as { body: string }).body);
        return new Response(okBody(), { status: 200 });
      }) as typeof fetch,
    });
    const out = await c.decide(ir());
    expect(out.status).toBe("ok");
    expect(capturedUrl).toBe("https://jev.internal.example.com/decide");
    expect(JSON.parse(capturedBody).model).toBe("custom-jev");
    expect("HTTP-Referer" in headers).toBe(false);
    expect("X-Title" in headers).toBe(false);
  });
});

describe("CompositeAdvisoryClient", () => {
  const ok = (name: string, verdict: LayaOutcome extends never ? never : { decision: "ALLOW" | "ASK" | "DENY"; confidence: number; reason: string; risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; injected?: boolean }) => ({
    name,
    decide: async () => ({ status: "ok" as const, verdict }),
  });
  const fail = (name: string) => ({
    name,
    decide: async () => ({ status: "failed" as const, kind: "http" as const, detail: "x" }),
  });
  it("strictest decision wins, risk=max, confidence=min", async () => {
    const c = new CompositeAdvisoryClient([
      ok("a", { decision: "ALLOW", confidence: 0.9, reason: "a", risk: "LOW" }),
      ok("b", { decision: "DENY", confidence: 0.7, reason: "b", risk: "HIGH" }),
    ]);
    const out = await c.decide(ir());
    expect(out).toMatchObject({ status: "ok" });
    if (out.status === "ok") {
      expect(out.verdict.decision).toBe("DENY");
      expect(out.verdict.risk).toBe("HIGH");
      expect(out.verdict.confidence).toBeCloseTo(0.7);
    }
  });
  it("propagates injected from any advisor", async () => {
    const c = new CompositeAdvisoryClient([
      ok("a", { decision: "ALLOW", confidence: 0.9, reason: "a", risk: "LOW" }),
      ok("b", { decision: "ALLOW", confidence: 0.9, reason: "b", risk: "LOW", injected: true }),
    ]);
    const out = await c.decide(ir());
    if (out.status === "ok") expect(out.verdict.injected).toBe(true);
    else throw new Error("expected ok");
  });
  it("one ok + one failure still decides", async () => {
    const c = new CompositeAdvisoryClient([
      fail("a"),
      ok("b", { decision: "ASK", confidence: 0.6, reason: "b", risk: "MEDIUM" }),
    ]);
    expect(await c.decide(ir())).toMatchObject({ status: "ok" });
  });
  it("all fail -> failed", async () => {
    const c = new CompositeAdvisoryClient([fail("a"), fail("b")]);
    expect(await c.decide(ir())).toMatchObject({ status: "failed" });
  });
});

describe("service wiring", () => {
  it("jev enabled with key selects jev client", () => {
    const s = new SmartPermissionsService({ jevEnabled: true, jevApiKey: "k" });
    expect(s.laya.name).toBe("jev.openrouter");
    expect(s.stats().laya).toBe("jev.openrouter");
  });
  it("both enabled selects composite", () => {
    const s = new SmartPermissionsService({ jevEnabled: true, jevApiKey: "k", layaEnabled: true });
    expect(s.laya.name).toBe("advisory.composite");
  });
  it("defaults point at the Zen free tier", async () => {
    const { defaultSettings } = await import("../shared/config.js");
    expect(defaultSettings().jevEndpoint).toBe("https://opencode.ai/zen/v1/systemone");
    expect(defaultSettings().jevModel).toBe("jev-1.13-free");
    expect(JEV_DEFAULT_ENDPOINT).toBe("https://opencode.ai/zen/v1/systemone");
    expect(JEV_DEFAULT_MODEL).toBe("jev-1.13-free");
  });
  it("jev enabled without key stays disabled (no unauthenticated calls)", () => {
    const s = new SmartPermissionsService({ jevEnabled: true, jevApiKey: "" });
    expect(s.laya.name).toBe("laya.disabled");
  });
  it("defaults prefer jev over laya (laya stays opt-in)", () => {
    const s = new SmartPermissionsService({ jevApiKey: "k" });
    expect(s.settings.jevEnabled).toBe(true);
    expect(s.settings.layaEnabled).toBe(false);
    expect(s.laya.name).toBe("jev.openrouter");
  });
  it("rejects out-of-range jev settings", () => {
    const s = new SmartPermissionsService({});
    expect(s.applySettings({ ...s.settings, jevTimeoutMs: -5 })).not.toBeNull();
  });
});
