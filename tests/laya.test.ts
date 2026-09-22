import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { DisabledLayaClient, HttpLayaClient, LAYA_VERDICT_SCHEMA, buildLayaPayload } from "../server/laya.js";
import { agent, shell } from "./helpers.js";

const ir = () => buildIR({ request: shell("npm test"), agent: agent() });

describe("laya schema", () => {
  it("accepts valid verdicts", () => {
    expect(LAYA_VERDICT_SCHEMA.safeParse({ decision: "ALLOW", confidence: 0.9, reason: "ok", risk: "LOW" }).success).toBe(true);
  });
  it("rejects bad enum / range / long reason / missing fields", () => {
    expect(LAYA_VERDICT_SCHEMA.safeParse({ decision: "MAYBE", confidence: 0.9, reason: "x", risk: "LOW" }).success).toBe(false);
    expect(LAYA_VERDICT_SCHEMA.safeParse({ decision: "ALLOW", confidence: 2, reason: "x", risk: "LOW" }).success).toBe(false);
    expect(LAYA_VERDICT_SCHEMA.safeParse({ decision: "ALLOW", confidence: 0.5, reason: "x".repeat(600), risk: "LOW" }).success).toBe(false);
    expect(LAYA_VERDICT_SCHEMA.safeParse({ decision: "ALLOW", confidence: 0.5, risk: "LOW" }).success).toBe(false);
  });
});

describe("laya clients", () => {
  it("disabled client reports disabled", async () => {
    const out = await new DisabledLayaClient().decide(ir());
    expect(out.status).toBe("failed");
  });
  it("maps ok verdicts", async () => {
    const c = new HttpLayaClient({
      endpoint: "http://127.0.0.1:1/nope", token: "t", timeoutMs: 3000,
      fetchImpl: (async () => new Response(JSON.stringify({ decision: "ASK", confidence: 0.5, reason: "unsure", risk: "MEDIUM" }), { status: 200 })) as typeof fetch,
    });
    const out = await c.decide(ir());
    expect(out.status).toBe("ok");
  });
  it("invalid JSON body -> invalid failure", async () => {
    const c = new HttpLayaClient({
      endpoint: "http://x", token: "t", timeoutMs: 3000,
      fetchImpl: (async () => new Response(JSON.stringify({ decision: "SURE" }), { status: 200 })) as typeof fetch,
    });
    const out = await c.decide(ir());
    expect(out).toMatchObject({ status: "failed", kind: "invalid" });
  });
  it("sends bearer token", async () => {
    let auth: string | null = null;
    const c = new HttpLayaClient({
      endpoint: "http://x", token: "sekret", timeoutMs: 3000,
      fetchImpl: (async (_u: unknown, init: unknown) => {
        auth = (init as { headers: Record<string, string> }).headers.authorization;
        return new Response(JSON.stringify({ decision: "ASK", confidence: 0.5, reason: "u", risk: "LOW" }), { status: 200 });
      }) as typeof fetch,
    });
    await c.decide(ir());
    expect(auth).toBe("Bearer sekret");
  });
  it("timeout maps to timeout failure", async () => {
    const c = new HttpLayaClient({
      endpoint: "http://x", token: "t", timeoutMs: 50,
      fetchImpl: (((_u: unknown, init: unknown) => new Promise((_res, rej) => {
        const signal = (init as { signal: AbortSignal }).signal;
        const onAbort = () => {
          const e = new Error("aborted"); e.name = "AbortError"; rej(e);
        };
        if (signal.aborted) { onAbort(); return; }
        signal.addEventListener("abort", onAbort, { once: true });
      })) as unknown) as typeof fetch,
    });
    const out = await c.decide(ir());
    expect(out.status).toBe("failed");
  });
  it("circuit opens after 5 failures", async () => {
    const c = new HttpLayaClient({
      endpoint: "http://x", token: "t", timeoutMs: 1000,
      fetchImpl: (async () => new Response("nope", { status: 500 })) as typeof fetch,
    });
    for (let i = 0; i < 5; i++) await c.decide(ir());
    expect(c.circuitOpen).toBe(true);
  });
});

describe("laya payload (typed-decision contract)", () => {
  it("matches the typed-decision contract keys", async () => {
    const { buildIR } = await import("../server/ir.js");
    const ir = buildIR({ request: shell("npm test"), agent: agent() });
    const p = buildLayaPayload(ir);
    expect(p.schema).toBe("smart-permissions.laya.v1");
    expect(Object.keys(p.request).sort()).toEqual(
      ["action", "capability", "command", "hosts", "paths", "risk", "riskReasons", "tool", "untrusted", "workspace"].sort(),
    );
    expect("system" in p).toBe(false);
    expect("summary" in p.request).toBe(false);
  });
  it("sanitizes raw command (no secrets cross the wire)", async () => {
    const { buildIR } = await import("../server/ir.js");
    const ir = buildIR({ request: shell("export TOKEN=sk-abcdefghijklmnop1234 && deploy"), agent: agent() });
    const p = buildLayaPayload(ir);
    expect(JSON.stringify(p)).not.toContain("abcdefghijklmnop");
  });
  it("accepts server verdict extras (injected/routing)", () => {
    const r = LAYA_VERDICT_SCHEMA.safeParse({
      decision: "ASK", confidence: 0.7, reason: "x", risk: "MEDIUM",
      injected: false, routing: { model: "english" }, extra_future: 1,
    });
    expect(r.success).toBe(true);
  });
});
