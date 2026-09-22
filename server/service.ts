/** SmartPermissionsService: SDK-agnostic orchestration (fully unit-testable).
 *  index.server.ts only wires real Paseo hooks to this class. */
import type {
  AgentPermissionRequest, AgentPermissionResponse,
} from "@getpaseo/protocol/agent-types";
import { buildIR, type PermissionIR } from "./ir.js";
import { DecisionCache } from "./cache.js";
import { AuditLogger } from "./audit.js";
import { DecisionEngine, type FinalDecision } from "./engine.js";
import { DisabledLayaClient, HttpLayaClient, advisorDisplayName, type LayaClient } from "./laya.js";
import { HttpJevClient } from "./jev.js";
import { CompositeAdvisoryClient } from "./advisors.js";
import { LearnedStore, type UserRule, defaultUserRules } from "./rules.js";
import {
  SETTINGS_VERSION, coerceUserRules, defaultSettings, parseSettings, validateUserRules, type PluginSettings,
} from "../shared/config.js";

export interface AgentInfo { id: string; provider: string; cwd: string; workspaceId: string | null; }
export type RespondFn = (
  agentId: string, requestId: string, response: AgentPermissionResponse,
) => Promise<void>;

export const DECIDE_TIMEOUT_MS = 20_000;
export const RECENT_IR_CAPACITY = 500;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const gate = new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), ms); });
  return Promise.race([p, gate]).finally(() => { if (timer) clearTimeout(timer); });
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class SmartPermissionsService {
  settings: PluginSettings;
  rulesVersion = 1;
  engine: DecisionEngine;
  learned = new LearnedStore();
  cache = new DecisionCache();
  audit = new AuditLogger();
  laya: LayaClient = new DisabledLayaClient();
  counts = { allow: 0, ask: 0, deny: 0 };

  /** requestId -> IR, for learning from permission_resolved. Bounded. */
  private recentIR = new Map<string, PermissionIR>();

  constructor(initial?: Partial<PluginSettings>) {
    this.settings = { ...defaultSettings(), ...(initial ?? {}) };
    if (!this.settings.layaToken) this.settings.layaToken = randomToken();
    this.engine = this.buildEngine();
  }

  private buildEngine(): DecisionEngine {
    const userRules: UserRule[] = [...defaultUserRules(), ...coerceUserRules(this.settings.userRules)];
    this.cache = new DecisionCache(this.settings.cacheTtlSec * 1000);
    // Advisory providers: Jev (OpenRouter Decisions API) and/or Laya (local HTTP).
    // Both implement the same typed-decision interface; when both are on,
    // a composite merges them conservatively (strictest decision wins).
    const advisors: LayaClient[] = [];
    if (this.settings.jevEnabled && this.settings.jevApiKey) {
      advisors.push(new HttpJevClient({
        endpoint: this.settings.jevEndpoint,
        model: this.settings.jevModel,
        apiKey: this.settings.jevApiKey,
        timeoutMs: this.settings.jevTimeoutMs,
      }));
    }
    if (this.settings.layaEnabled) {
      advisors.push(new HttpLayaClient({
        endpoint: this.settings.layaEndpoint,
        token: this.settings.layaToken,
        timeoutMs: this.settings.layaTimeoutMs,
      }));
    }
    const laya: LayaClient = advisors.length === 0
      ? new DisabledLayaClient()
      : advisors.length === 1 ? advisors[0] : new CompositeAdvisoryClient(advisors);
    this.laya = laya;
    return new DecisionEngine({
      userRules,
      learned: this.learned,
      laya,
      cache: this.cache,
      rulesVersion: this.rulesVersion,
      learningEnabled: this.settings.learningEnabled,
      defaultPolicy: this.settings.defaultPolicy,
      maxConcurrency: this.settings.layaMaxConcurrency,
      // Conservative: the stricter confidence bar governs when both are active.
      minConfidence: Math.max(this.settings.layaMinConfidence, this.settings.jevMinConfidence),
    });
  }

  /** Hot-apply new settings (from config.update RPC). Returns error string or null. */
  applySettings(input: unknown): string | null {
    let parsed: PluginSettings;
    try {
      parsed = parseSettings(input);
    } catch (e) {
      return e instanceof Error ? e.message : "invalid settings";
    }
    if (!parsed.layaToken) parsed.layaToken = this.settings.layaToken || randomToken();
    const { issues } = validateUserRules(parsed.userRules);
    if (issues.length > 0) {
      const detail = issues.map((i) => `rule #${i.index + 1}: ${i.messages.join("; ")}`).join(" | ");
      return `invalid user rules (${detail})`;
    }
    this.settings = parsed;
    this.rulesVersion += 1;
    this.engine = this.buildEngine(); // rebuilds cache (invalidated) + laya client
    return null;
  }

  /** Main entry: called from agent.permission_requested. ASK = no respond call. */
  async onPermissionRequested(
    request: AgentPermissionRequest, agent: AgentInfo, respond: RespondFn,
  ): Promise<{ decision: FinalDecision; responded: boolean }> {
    const started = Date.now();
    if (!this.settings.enabled) {
      // No engine call here: the result would be discarded and the advisor
      // roundtrip would only delay the native UI for nothing.
      const ir = buildIR({ request, agent });
      const ask: FinalDecision = {
        decision: "ASK", source: "DEFAULT", reason: "plugin disabled; leaving to native UI",
        risk: ir.risk, matchedRules: [], interrupt: false, fallback: false, cached: false,
      };
      this.rememberIR(ir);
      this.audit.record(ir, ask, { laya: "disabled:plugin-off", latencyMs: Date.now() - started, fallback: false });
      this.counts.ask += 1;
      return { decision: ask, responded: false };
    }

    const ir = buildIR({ request, agent });
    this.rememberIR(ir);
    const decided = await withTimeout(this.engine.decide(ir), DECIDE_TIMEOUT_MS);
    const latencyMs = Date.now() - started;
    const layaLabel = this.laya.name;

    if (!decided) {
      // Engine-level timeout (should be unreachable since Laya has its own timeout,
      // but defense in depth): fail to ASK, never hang the agent.
      const ask: FinalDecision = {
        decision: "ASK", source: "FALLBACK", reason: "decision timeout; escalated to human review",
        risk: ir.risk, matchedRules: ["engine-timeout"], interrupt: false, fallback: true, cached: false,
      };
      this.audit.record(ir, ask, { laya: layaLabel, latencyMs, fallback: true });
      this.counts.ask += 1;
      return { decision: ask, responded: false };
    }

    this.audit.record(ir, decided, { laya: layaLabel, latencyMs, fallback: decided.fallback });
    if (decided.decision === "ALLOW") {
      this.counts.allow += 1;
      await respond(agent.id, request.id, { behavior: "allow" });
      return { decision: decided, responded: true };
    }
    if (decided.decision === "DENY") {
      this.counts.deny += 1;
      await respond(agent.id, request.id, { behavior: "deny", interrupt: false });
      return { decision: decided, responded: true };
    }
    this.counts.ask += 1;
    return { decision: decided, responded: false }; // ASK: leave pending for native UI
  }

  /** Called from agent.permission_resolved — feeds Learned Rules from human choices. */
  onPermissionResolved(requestId: string, resolution: AgentPermissionResponse): void {
    const ir = this.recentIR.get(requestId);
    if (!ir) return;
    this.engine.learn(ir, resolution.behavior);
  }

  /** Dry-run a synthetic request (preview RPC). No side effects except audit? No audit. */
  async preview(input: {
    provider: string; toolName: string; kind: "tool" | "plan" | "question" | "mode" | "other";
    cwd: string; command?: string; filePath?: string; url?: string;
  }): Promise<FinalDecision> {
    const detail = input.command !== undefined
      ? { type: "shell", command: input.command } as const
      : input.filePath !== undefined
        ? { type: "read", filePath: input.filePath } as const
        : input.url !== undefined
          ? { type: "fetch", url: input.url } as const
          : { type: "unknown", input: {}, output: {} } as const;
    const request: AgentPermissionRequest = {
      id: `preview-${Date.now()}`, provider: input.provider, name: input.toolName,
      kind: input.kind, detail: detail as never,
    };
    const ir = buildIR({ request, agent: { id: "preview", provider: input.provider, cwd: input.cwd, workspaceId: null } });
    return this.engine.decide(ir);
  }

  stats() {
    return {
      enabled: this.settings.enabled,
      total: this.counts.allow + this.counts.ask + this.counts.deny,
      ...this.counts,
      cacheHits: this.cache.hits,
      cacheMisses: this.cache.misses,
      cacheSize: this.cache.size(),
      learnedRules: this.learned.size(),
      rulesVersion: this.rulesVersion,
      laya: this.laya.name,
      advisor: advisorDisplayName(this.laya),
    };
  }

  settingsVersion(): number { return SETTINGS_VERSION; }

  private rememberIR(ir: PermissionIR): void {
    this.recentIR.set(ir.requestId, ir);
    if (this.recentIR.size > RECENT_IR_CAPACITY) {
      const oldest = this.recentIR.keys().next();
      if (!oldest.done) this.recentIR.delete(oldest.value);
    }
  }
}
