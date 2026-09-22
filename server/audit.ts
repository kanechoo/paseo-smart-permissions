/** Audit log: every auto-decision recorded, secrets never persisted. */
import { sanitize, truncate } from "./redact.js";
import type { FinalDecision } from "./engine.js";
import type { PermissionIR } from "./ir.js";

export interface AuditEntry {
  timestamp: string;
  requestId: string;
  provider: string;
  agentId: string;
  workspace: string;
  capability: string;
  action: string;
  target: string;          // sanitized + truncated
  risk: string;
  riskReasons: string[];
  matchedRules: string[];
  laya: string;            // ok:ALLOW / failed:timeout / disabled ...
  finalDecision: string;
  decisionSource: string;
  reason: string;
  latencyMs: number;
  fallback: boolean;
}

export class AuditLogger {
  private entries: AuditEntry[] = [];
  constructor(private capacity = 1000) {}

  record(ir: PermissionIR, decision: FinalDecision, opts: {
    laya: string; latencyMs: number; fallback: boolean;
  }): AuditEntry {
    const target = truncate(
      sanitize(ir.command ?? ir.paths.join(", ") ?? ir.network?.urls.join(", ") ?? ir.toolName, 300),
      300,
    );
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      requestId: sanitize(ir.requestId, 120),
      provider: ir.provider,
      agentId: sanitize(ir.agentId, 120),
      workspace: sanitize(ir.workspaceCwd, 300),
      capability: ir.capability,
      action: sanitize(ir.action, 120),
      target,
      risk: decision.risk,
      riskReasons: ir.riskReasons.map((r) => truncate(sanitize(r, 300), 300)),
      matchedRules: [...decision.matchedRules],
      laya: opts.laya,
      finalDecision: decision.decision,
      decisionSource: decision.source,
      reason: truncate(sanitize(decision.reason, 500), 500),
      latencyMs: opts.latencyMs,
      fallback: opts.fallback,
    };
    this.entries.push(entry);
    if (this.entries.length > this.capacity) this.entries.splice(0, this.entries.length - this.capacity);
    return entry;
  }

  recent(n = 50): AuditEntry[] { return this.entries.slice(-n).reverse(); }
  count(): number { return this.entries.length; }
}
