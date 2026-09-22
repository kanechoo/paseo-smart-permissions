/** Decision cache: only LOW/MEDIUM ALLOW + hard-deny DENY; ASK never cached. */
import { sanitize } from "./redact.js";
import type { PermissionIR } from "./ir.js";
import type { FinalDecision } from "./engine.js";

export interface CacheEntry { decision: FinalDecision; expiresAt: number; }

export function cacheKey(ir: PermissionIR, rulesVersion: number): string {
  const target = sanitize(
    ir.command ?? ir.paths.join(",") ?? ir.network?.hosts.join(",") ?? ir.toolName,
    400,
  );
  return [ir.provider, ir.capability, target, ir.workspaceCwd, String(rulesVersion)].join("|").toLowerCase();
}

export class DecisionCache {
  private entries = new Map<string, CacheEntry>();
  hits = 0; misses = 0;

  constructor(private ttlMs = 60_000, private now: () => number = Date.now) {}

  get(key: string): FinalDecision | undefined {
    const e = this.entries.get(key);
    if (!e) { this.misses += 1; return undefined; }
    if (e.expiresAt <= this.now()) { this.entries.delete(key); this.misses += 1; return undefined; }
    this.hits += 1;
    return e.decision;
  }

  /** Returns true if stored. Refuses ASK and HIGH/CRITICAL ALLOW. */
  set(key: string, decision: FinalDecision): boolean {
    if (decision.decision === "ASK") return false;
    if (decision.decision === "ALLOW" && (decision.risk === "HIGH" || decision.risk === "CRITICAL")) return false;
    this.entries.set(key, { decision, expiresAt: this.now() + this.ttlMs });
    return true;
  }

  invalidateAll(): void { this.entries.clear(); }
  size(): number { return this.entries.size; }
}
