import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { DecisionCache } from "../server/cache.js";
import { DecisionEngine } from "../server/engine.js";
import { DisabledLayaClient } from "../server/laya.js";
import { LearnedStore } from "../server/rules.js";
import { agent, shell } from "./helpers.js";

describe("perf regression gates", () => {
  it("rule-only p99 under 50ms", async () => {
    const engine = new DecisionEngine({
      userRules: [{ id: "u", effect: "allow", commandPattern: "npm test" }],
      learned: new LearnedStore(), laya: new DisabledLayaClient(),
      cache: new DecisionCache(60000), rulesVersion: 1, learningEnabled: true,
      defaultPolicy: "ask", maxConcurrency: 4, minConfidence: 0.6,
    });
    const lat: number[] = [];
    for (let i = 0; i < 100; i++) {
      const t = Date.now();
      await engine.decide(buildIR({ request: shell(`npm test --case=${i}`), agent: agent() }));
      lat.push(Date.now() - t);
    }
    lat.sort((a, b) => a - b);
    expect(lat[Math.floor(lat.length * 0.99)]).toBeLessThan(50);
  });
  it("50 concurrent e2e settle under 5s", async () => {
    const engine = new DecisionEngine({
      userRules: [], learned: new LearnedStore(), laya: new DisabledLayaClient(),
      cache: new DecisionCache(60000), rulesVersion: 1, learningEnabled: true,
      defaultPolicy: "ask", maxConcurrency: 4, minConfidence: 0.6,
    });
    const t = Date.now();
    await Promise.all(Array.from({ length: 50 }, (_, i) =>
      engine.decide(buildIR({ request: shell(`echo ${i} && npm test`), agent: agent() }))));
    expect(Date.now() - t).toBeLessThan(5000);
  }, 10000);
});
