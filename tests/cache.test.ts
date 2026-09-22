import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { DecisionCache, cacheKey } from "../server/cache.js";
import type { FinalDecision } from "../server/engine.js";
import { agent, shell } from "./helpers.js";

const allowLow: FinalDecision = { decision: "ALLOW", source: "LAYA", reason: "r", risk: "LOW", matchedRules: ["laya"], interrupt: false, fallback: false, cached: false };
const allowHigh: FinalDecision = { ...allowLow, risk: "HIGH" };
const ask: FinalDecision = { ...allowLow, decision: "ASK", source: "DEFAULT" };

describe("cache", () => {
  it("stable keys, version-sensitive", () => {
    const ir = buildIR({ request: shell("npm test"), agent: agent() });
    expect(cacheKey(ir, 1)).toBe(cacheKey(ir, 1));
    expect(cacheKey(ir, 1)).not.toBe(cacheKey(ir, 2));
  });
  it("stores LOW ALLOW, refuses ASK and HIGH ALLOW", () => {
    const c = new DecisionCache(60000);
    expect(c.set("k1", allowLow)).toBe(true);
    expect(c.get("k1")).toBeDefined();
    expect(c.set("k2", ask)).toBe(false);
    expect(c.set("k3", allowHigh)).toBe(false);
  });
  it("expires entries", () => {
    let now = 0;
    const c = new DecisionCache(100, () => now);
    c.set("k", allowLow);
    now = 200;
    expect(c.get("k")).toBeUndefined();
  });
});
