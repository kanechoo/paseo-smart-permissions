/** Composite advisory client: conservative merge of multiple DecisionProviders.
 *  Used when both Laya and Jev are enabled. Merge rule (fail-safe):
 *  - any ok verdict counts; total failure only if ALL advisors fail;
 *  - decision = strictest (DENY > ASK > ALLOW);
 *  - risk = max; confidence = min; injected = any;
 *  - reason = joined, truncated to 500 chars. */
import type { LayaClient, LayaOutcome, LayaVerdict } from "./laya.js";
import { maxRisk } from "./ir.js";
import type { PermissionIR } from "./ir.js";

const STRICTNESS = { DENY: 3, ASK: 2, ALLOW: 1 } as const;

export class CompositeAdvisoryClient implements LayaClient {
  readonly name = "advisory.composite";

  constructor(private advisors: LayaClient[]) {
    if (advisors.length === 0) throw new Error("CompositeAdvisoryClient needs at least one advisor");
  }

  get inner(): readonly LayaClient[] { return this.advisors; }

  async decide(ir: PermissionIR): Promise<LayaOutcome> {
    const settled = await Promise.all(this.advisors.map((a) => a.decide(ir)));
    const verdicts: Array<{ from: string; verdict: LayaVerdict }> = [];
    const failures: string[] = [];
    settled.forEach((out, i) => {
      if (out.status === "ok") verdicts.push({ from: this.advisors[i].name, verdict: out.verdict });
      else failures.push(`${this.advisors[i].name}:${out.kind}`);
    });
    if (verdicts.length === 0) {
      return { status: "failed", kind: "network", detail: `all advisors failed (${failures.join(", ")})` };
    }
    let decision = verdicts[0].verdict.decision;
    let risk = verdicts[0].verdict.risk;
    let confidence = verdicts[0].verdict.confidence;
    let injected = verdicts[0].verdict.injected === true;
    const parts = verdicts.map(({ from, verdict: v }) => `${from}=${v.decision}/${v.confidence.toFixed(2)}/${v.risk}`);
    for (const { verdict: v } of verdicts) {
      if (STRICTNESS[v.decision] > STRICTNESS[decision]) decision = v.decision;
      risk = maxRisk(risk, v.risk);
      confidence = Math.min(confidence, v.confidence);
      if (v.injected === true) injected = true;
    }
    const reason = `composite[${verdicts.length}] ${parts.join(" ")}`.slice(0, 500);
    return { status: "ok", verdict: { decision, confidence, reason, risk, injected } };
  }
}
