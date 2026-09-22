/** Three-tier rule system: Hard (deny-only, unoverridable) > User > Learned. */
import { analyzeCommand, isKnownSafeCommand } from "./commands.js";
import { classifyPaths } from "./paths.js";
import type { PermissionIR, RiskLevel } from "./ir.js";
import { maxRisk } from "./ir.js";

export interface RuleHit { ruleId: string; reason: string; }

/* ---------------- Hard rules (DENY only) ---------------- */

export interface HardRule { id: string; describe: string; test(ir: PermissionIR): string | null; }

const HARD_RULES: HardRule[] = [
  {
    id: "hard.secret-file", describe: "Block access to credential/secret files",
    test: (ir) => {
      if (ir.paths.length === 0) return null;
      const c = classifyPaths(ir.workspaceCwd, ir.paths);
      if (c.secretFile) return `secret file access blocked: ${c.reasons.filter((r) => r.startsWith("secret")).join("; ")}`;
      return null;
    },
  },
  {
    id: "hard.sensitive-path", describe: "Block system/credential directories",
    test: (ir) => {
      if (ir.paths.length === 0) return null;
      const c = classifyPaths(ir.workspaceCwd, ir.paths);
      if (c.sensitive) return `sensitive path blocked: ${c.reasons.filter((r) => r.startsWith("sensitive")).join("; ")}`;
      if (c.symlinkEscape) return `symlink escape blocked: ${c.reasons.filter((r) => r.startsWith("symlink")).join("; ")}`;
      return null;
    },
  },
  {
    id: "hard.workspace-escape-write", describe: "Block writes/deletes outside workspace",
    test: (ir) => {
      const mutating = ir.capability === "file.write" || ir.capability === "file.delete" || ir.capability === "file.exec";
      if (!mutating || ir.paths.length === 0) return null;
      const c = classifyPaths(ir.workspaceCwd, ir.paths);
      if (c.escape || c.unresolvable) return `workspace escape blocked: ${c.reasons.join("; ")}`;
      return null;
    },
  },
  {
    id: "hard.critical-command", describe: "Block destructive/privilege-escalation commands",
    test: (ir) => {
      if (ir.capability !== "shell.exec" || !ir.command) return null;
      const a = analyzeCommand(ir.command);
      if (a.danger === "CRITICAL") return `dangerous command blocked: ${a.dangerReasons.join(", ")}`;
      return null;
    },
  },
  {
    id: "hard.pipe-to-shell", describe: "Block curl|sh style remote-code execution",
    test: (ir) => {
      if (ir.capability !== "shell.exec" || !ir.command) return null;
      const a = analyzeCommand(ir.command);
      if (a.hasPipeToShell) return `remote code execution blocked: ${ir.command.slice(0, 200)}`;
      return null;
    },
  },
  {
    id: "hard.git-destructive", describe: "Block destructive git ops without explicit user rule",
    test: (ir) => {
      if (ir.capability !== "shell.exec" || !ir.command) return null;
      const cmd = ir.command.toLowerCase();
      if (/\bgit\s+push\b.*--force/.test(cmd)) return "git push --force blocked (needs explicit user rule)";
      if (/\bgit\s+reset\s+--hard/.test(cmd)) return "git reset --hard blocked (needs explicit user rule)";
      if (/\bgit\s+clean\s+-[a-z]*f/.test(cmd)) return "git clean -f blocked (needs explicit user rule)";
      return null;
    },
  },
];

export function matchHardDeny(ir: PermissionIR): RuleHit | null {
  for (const r of HARD_RULES) {
    const reason = r.test(ir);
    if (reason) return { ruleId: r.id, reason };
  }
  return null;
}

/* ---------------- User rules ---------------- */

import type { UserRule, UserRuleEffect } from "../shared/config.js";
export type { UserRule, UserRuleEffect };

function globToRegExp(glob: string): RegExp {
  let re = "^";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === "*") {
      if (glob[i + 1] === "*") { re += ".*"; i++; }
      else re += "[^/]*";
    } else if ("+?^${}()|[]\\.".includes(ch)) re += `\\${ch}`;
    else re += ch;
  }
  return new RegExp(re + "$", "i");
}

function commandMatches(pattern: string, command: string): boolean {
  if (pattern.startsWith("/") && pattern.endsWith("/") && pattern.length > 2) {
    return new RegExp(pattern.slice(1, -1), "i").test(command);
  }
  return command.toLowerCase().includes(pattern.toLowerCase());
}

export function matchUserRule(ir: PermissionIR, rule: UserRule): boolean {
  if (rule.provider && rule.provider !== "*" && rule.provider !== ir.provider) return false;
  if (rule.capability && rule.capability !== "*" && rule.capability !== ir.capability) return false;
  if (rule.workspace) {
    // Boundary-aware prefix: "/w/project" must match "/w/project/a" but NOT
    // the sibling "/w/project2" (plain startsWith over-matches). Trailing
    // slashes are normalized on both sides.
    const norm = (v: string) => (v.endsWith("/") && v.length > 1 ? v.slice(0, -1) : v);
    const w = norm(rule.workspace);
    const cwd = norm(ir.workspaceCwd);
    if (cwd !== w && !cwd.startsWith(`${w}/`)) return false;
  }
  if (rule.commandPattern) {
    if (!ir.command || !commandMatches(rule.commandPattern, ir.command)) return false;
  }
  if (rule.pathPattern) {
    if (ir.paths.length === 0) return false;
    const re = globToRegExp(rule.pathPattern);
    if (!ir.paths.some((p) => re.test(p))) return false;
  }
  if (rule.hostPattern) {
    const hosts = ir.network?.hosts ?? [];
    if (hosts.length === 0) return false;
    if (!hosts.some((h) => h.includes(rule.hostPattern!.toLowerCase()))) return false;
  }
  return true;
}

/** Built-in safe defaults shipped as user-allow rules (user can delete). */
export function defaultUserRules(): UserRule[] {
  return [
    { id: "user.git-readonly", effect: "allow", capability: "file.read" },
    { id: "user.local-search", effect: "allow", capability: "file.read" },
  ];
}

/* ---------------- Learned rules ---------------- */

export interface LearnedRule {
  key: string;            // scope key
  effect: "allow";
  capability: string;
  observations: number;
  firstSeen: number;
  lastSeen: number;
  expiresAt: number;
}

export interface LearnedConfig { minObservations: number; ttlMs: number; }

export const DEFAULT_LEARNED_CONFIG: LearnedConfig = {
  minObservations: 2,
  ttlMs: 7 * 24 * 3600 * 1000,
};

export function learnedKey(ir: PermissionIR): string {
  const target = ir.command ?? ir.paths[0] ?? ir.network?.hosts?.[0] ?? ir.toolName;
  return `${ir.provider}|${ir.capability}|${target}`.toLowerCase();
}

export class LearnedStore {
  private rules = new Map<string, LearnedRule>();
  constructor(private config: LearnedConfig = DEFAULT_LEARNED_CONFIG) {}

  /** Record a human resolution (from permission_resolved). Only LOW-risk allows are learnable. */
  observe(ir: PermissionIR, behavior: "allow" | "deny", risk: RiskLevel, now = Date.now()): void {
    if (behavior !== "allow" || risk !== "LOW") return;
    const key = learnedKey(ir);
    const prev = this.rules.get(key);
    if (prev) {
      prev.observations += 1;
      prev.lastSeen = now;
      prev.expiresAt = now + this.config.ttlMs;
    } else {
      this.rules.set(key, {
        key, effect: "allow", capability: ir.capability,
        observations: 1, firstSeen: now, lastSeen: now, expiresAt: now + this.config.ttlMs,
      });
    }
  }

  /** LOW-risk only, needs minObservations, must not be expired. Never overrides explicit rules. */
  match(ir: PermissionIR, now = Date.now()): LearnedRule | null {
    if (ir.risk !== "LOW") return null;
    const r = this.rules.get(learnedKey(ir));
    if (!r) return null;
    if (r.expiresAt <= now) { this.rules.delete(r.key); return null; }
    if (r.observations < this.config.minObservations) return null;
    return r;
  }

  revoke(key: string): boolean { return this.rules.delete(key); }
  size(): number { return this.rules.size; }
  export(): LearnedRule[] { return [...this.rules.values()]; }
}

/* ---------------- Helpers ---------------- */

/** Extra deterministic signal: well-known safe commands count as LOW evidence.
 *  Same gate as the IR baseline (single allowlisted command, no chains/
 *  substitution/redirect/secret hints) so the two can never diverge. */
export function baselineRisk(ir: PermissionIR): RiskLevel {
  if (ir.capability === "shell.exec" && ir.command && isKnownSafeCommand(ir.command)) {
    return "LOW";
  }
  void maxRisk;
  return ir.risk;
}
