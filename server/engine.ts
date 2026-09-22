/** Decision Engine: Hard Deny > User Deny > User Allow > Learned > Advisory (Jev/Laya) > Default.
 *  Never throws, never hangs (all awaits bounded by callers/Laya timeouts). */
import { maxRisk, type PermissionIR, type RiskLevel } from "./ir.js";
import { classifyPaths } from "./paths.js";
import {
  LearnedStore, matchHardDeny, matchUserRule, type UserRule,
} from "./rules.js";
import { DecisionCache, cacheKey } from "./cache.js";
import type { LayaClient } from "./laya.js";
import { advisorDisplayName, advisorTag } from "./laya.js";

export type Decision = "ALLOW" | "ASK" | "DENY";
export type DecisionSource =
  | "HARD_RULE" | "USER_RULE" | "LEARNED_RULE" | "LAYA" | "FALLBACK" | "DEFAULT" | "CACHE";

export interface FinalDecision {
  decision: Decision;
  source: DecisionSource;
  reason: string;
  risk: RiskLevel;
  matchedRules: string[];
  interrupt: boolean;
  fallback: boolean;
  cached: boolean;
}

export interface EngineOptions {
  userRules: UserRule[];
  learned: LearnedStore;
  laya: LayaClient;
  cache: DecisionCache;
  rulesVersion: number;
  learningEnabled: boolean;
  /** What to do when nothing can safely decide. "ask" keeps native UI. */
  defaultPolicy: "ask" | "deny";
  maxConcurrency: number;
  /** Laya verdicts below this calibrated confidence degrade to ASK (both directions). */
  minConfidence: number;
}

function deny(reason: string, source: DecisionSource, risk: RiskLevel, matchedRules: string[], fallback: boolean): FinalDecision {
  return { decision: "DENY", source, reason, risk, matchedRules, interrupt: false, fallback, cached: false };
}
function ask(reason: string, source: DecisionSource, risk: RiskLevel, matchedRules: string[], fallback: boolean): FinalDecision {
  return { decision: "ASK", source, reason, risk, matchedRules, interrupt: false, fallback, cached: false };
}

export class DecisionEngine {
  private inflight = new Map<string, Promise<FinalDecision>>();
  private layaSlots: number;
  private layaQueue: Array<() => void> = [];

  constructor(private options: EngineOptions) {
    this.layaSlots = Math.max(1, options.maxConcurrency);
  }

  updateOptions(patch: Partial<EngineOptions>): void {
    Object.assign(this.options, patch);
    if (patch.maxConcurrency !== undefined) this.layaSlots = Math.max(1, patch.maxConcurrency);
  }

  private async withLayaSlot<T>(fn: () => Promise<T>): Promise<T> {
    if (this.layaSlots > 0) {
      this.layaSlots -= 1;
      try { return await fn(); }
      finally {
        this.layaSlots += 1;
        const next = this.layaQueue.shift();
        if (next) next();
      }
    }
    await new Promise<void>((resolve) => this.layaQueue.push(resolve));
    return this.withLayaSlot(fn);
  }

  async decide(ir: PermissionIR): Promise<FinalDecision> {
    const key = cacheKey(ir, this.options.rulesVersion);
    const cached = this.options.cache.get(key);
    if (cached) return { ...cached, cached: true, source: "CACHE" };

    const existing = this.inflight.get(key);
    if (existing) return existing;

    const task = this.resolve(ir).then((d) => {
      // Cache only LOW/MEDIUM ALLOW and hard-deny DENY.
      if (d.decision === "ALLOW") this.options.cache.set(key, d);
      else if (d.decision === "DENY" && d.matchedRules.some((r) => r.startsWith("hard."))) {
        this.options.cache.set(key, d);
      }
      return d;
    }).finally(() => { this.inflight.delete(key); });
    this.inflight.set(key, task);
    return task;
  }

  private async resolve(ir: PermissionIR): Promise<FinalDecision> {
    // 1. Hard deny — unoverridable.
    const hard = matchHardDeny(ir);
    if (hard) {
      return deny(`Blocked by security rule ${hard.ruleId}: ${hard.reason}`, "HARD_RULE", "CRITICAL", [hard.ruleId], false);
    }

    // 2/3. Explicit user rules (deny first, then ask, then allow).
    for (const rule of this.options.userRules) {
      if (rule.effect === "deny" && matchUserRule(ir, rule)) {
        return deny(`Blocked by user rule ${rule.id}`, "USER_RULE", ir.risk, [rule.id], false);
      }
    }
    for (const rule of this.options.userRules) {
      if (rule.effect === "ask" && matchUserRule(ir, rule)) {
        // Force human review: skips learned/advisor auto-allow below.
        return ask(`Human review required by user rule ${rule.id}`, "USER_RULE", ir.risk, [rule.id], false);
      }
    }
    for (const rule of this.options.userRules) {
      if (rule.effect === "allow" && matchUserRule(ir, rule)) {
        // Defense in depth: a user ALLOW never silently releases operations
        // whose targets escape the workspace (reads included — hard rules only
        // cover writes). Such cases escalate to human review.
        if (ir.paths.length > 0) {
          const c = classifyPaths(ir.workspaceCwd, ir.paths);
          if (c.escape || c.unresolvable || c.symlinkEscape) {
            return ask(
              `User rule ${rule.id} matches but target escapes workspace; escalated to human review`,
              "DEFAULT", maxRisk(ir.risk, "MEDIUM"), [rule.id, "workspace-escape-guard"], false,
            );
          }
        }
        return {
          decision: "ALLOW", source: "USER_RULE",
          reason: `Allowed by user rule ${rule.id}`, risk: ir.risk,
          matchedRules: [rule.id], interrupt: false, fallback: false, cached: false,
        };
      }
    }

    // 4. Learned (LOW only, enforced inside store).
    if (this.options.learningEnabled) {
      const learned = this.options.learned.match(ir);
      if (learned) {
        return {
          decision: "ALLOW", source: "LEARNED_RULE",
          reason: `Allowed by learned pattern (${learned.observations} consistent approvals, expires ${new Date(learned.expiresAt).toISOString()})`,
          risk: ir.risk, matchedRules: [`learned:${learned.key}`],
          interrupt: false, fallback: false, cached: false,
        };
      }
    }

    // 5. Advisory signal (Jev and/or Laya share the typed-decision interface).
    // Reason strings must name the advisor that actually ran: a Jev-only user
    // must never see "Laya …" and conclude the wrong provider decided.
    const advisorName = advisorDisplayName(this.options.laya);
    const tag = advisorTag(this.options.laya);
    const laya = await this.withLayaSlot(() => this.options.laya.decide(ir));
    if (laya.status === "ok") {
      const v = laya.verdict;
      // Guard-model signal: prompt-injected content detected -> never ALLOW.
      if (v.injected === true) {
        return ask(
          `${advisorName} guard reports prompt injection; escalated to human review (${v.reason})`,
          "LAYA", maxRisk(ir.risk, v.risk), [tag, `${tag}-injection-guard`], false,
        );
      }
      const risk = maxRisk(ir.risk, v.risk);
      if (v.confidence < this.options.minConfidence) {
        return this.defaultAsk(
          `${advisorName} verdict ${v.decision} has confidence ${v.confidence.toFixed(2)} < ${this.options.minConfidence}; human review`,
          risk, [tag, "low-confidence"], false,
        );
      }
      if (v.decision === "DENY") {
        if (risk === "LOW") {
          return ask(`${advisorName} suggests DENY but risk is LOW; escalating to human review (${v.reason})`, "LAYA", risk, [tag], false);
        }
        return deny(`Denied by ${advisorName} advisory (${v.reason})`, "LAYA", risk, [tag], false);
      }
      if (v.decision === "ASK") {
        return this.defaultAsk(`${advisorName} defers to human review (${v.reason})`, risk, [tag], false);
      }
      // Advisory ALLOW: only effective for LOW/MEDIUM with sufficient confidence.
      if (risk === "LOW" || risk === "MEDIUM") {
        if (v.confidence < this.options.minConfidence) {
          return this.defaultAsk(
            `${advisorName} suggests ALLOW but confidence ${v.confidence.toFixed(2)} < ${this.options.minConfidence}; human review`,
            risk, [tag, "low-confidence"], false,
          );
        }
        return {
          decision: "ALLOW", source: "LAYA", reason: `Allowed by ${advisorName} advisory (${v.reason})`,
          risk, matchedRules: [tag], interrupt: false, fallback: false, cached: false,
        };
      }
      return this.defaultAsk(`${advisorName} suggests ALLOW but risk is ${risk}; escalating to human review`, risk, [tag], false);
    }

    // 6. Fallback (fail-closed).
    const layaLabel = `${tag}:${laya.kind}`;
    if (ir.risk === "HIGH" || ir.risk === "CRITICAL") {
      return deny(
        `${advisorName} unavailable (${laya.kind}: ${laya.detail}); failing closed on ${ir.risk} risk`,
        "FALLBACK", ir.risk, [layaLabel], true,
      );
    }
    return this.defaultAsk(`${advisorName} unavailable (${laya.kind}); human review required`, ir.risk, [layaLabel], true);
  }

  private defaultAsk(reason: string, risk: RiskLevel, matched: string[], fallback: boolean): FinalDecision {
    if (this.options.defaultPolicy === "deny") {
      return deny(`${reason} [defaultPolicy=deny]`, "DEFAULT", risk, matched, fallback);
    }
    return ask(reason, "DEFAULT", risk, matched, fallback);
  }

  /** Learn from a human resolution in Paseo UI (permission_resolved event). */
  learn(ir: PermissionIR, behavior: "allow" | "deny"): void {
    if (!this.options.learningEnabled) return;
    this.options.learned.observe(ir, behavior, ir.risk);
  }
}
