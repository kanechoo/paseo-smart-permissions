import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { AuditLogger } from "../server/audit.js";
import type { FinalDecision } from "../server/engine.js";
import { agent, shell } from "./helpers.js";

describe("audit", () => {
  it("records sanitized entries without secrets", () => {
    const log = new AuditLogger();
    const ir = buildIR({ request: shell("export TOKEN=sk-abcdefghijklmnop1234 && npm test"), agent: agent() });
    const d: FinalDecision = { decision: "ASK", source: "DEFAULT", reason: "r", risk: "MEDIUM", matchedRules: [], interrupt: false, fallback: false, cached: false };
    const e = log.record(ir, d, { laya: "disabled", latencyMs: 5, fallback: false });
    expect(JSON.stringify(e)).not.toContain("abcdefghijklmnop");
    expect(log.recent(10)).toHaveLength(1);
    expect(e.finalDecision).toBe("ASK");
  });
});
