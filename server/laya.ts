/** Laya: optional advisory DecisionProvider over HTTP localhost + token.
 *  Strict schema validation; every failure mode maps to a safe fallback. */
import { z } from "zod";
import { sanitize } from "./redact.js";
import type { PermissionIR } from "./ir.js";

export const LAYA_VERDICT_SCHEMA = z.object({
  decision: z.enum(["ALLOW", "ASK", "DENY"]),
  confidence: z.number().min(0).max(1),
  reason: z.string().max(500),
  risk: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  // Present when served by a to_verdict-compatible service; absent otherwise.
  injected: z.boolean().optional(),
  routing: z.record(z.string(), z.unknown()).optional(),
});
export type LayaVerdict = z.infer<typeof LAYA_VERDICT_SCHEMA>;

/** Typed-decision contract (see docs/smart-permissions-laya.md).
 *  No natural-language prompt is sent: Laya is not a generative LLM, it answers
 *  typed questions over this structured state in a single forward pass. */
export interface LayaRequestPayload {
  schema: "smart-permissions.laya.v1";
  request: {
    tool: string;
    capability: string;
    action: string;
    workspace: string;
    command: string;
    paths: string[];
    hosts: string[];
    risk: string;
    riskReasons: string[];
    untrusted: string[];
  };
}

export type LayaOutcome =
  | { status: "ok"; verdict: LayaVerdict }
  | { status: "failed"; kind: "disabled" | "timeout" | "network" | "http" | "invalid"; detail: string };

export interface LayaClient {
  readonly name: string;
  decide(ir: PermissionIR): Promise<LayaOutcome>;
}

export class DisabledLayaClient implements LayaClient {
  readonly name = "laya.disabled";
  async decide(_ir: PermissionIR): Promise<LayaOutcome> {
    void _ir;
    return { status: "failed", kind: "disabled", detail: "Laya integration is disabled" };
  }
}

export interface HttpLayaOptions {
  endpoint: string;
  token: string;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
}

export function buildLayaPayload(ir: PermissionIR): LayaRequestPayload {
  // ir.command is raw: sanitize here (paths carry names only, no content;
  // untrustedText was already sanitized at IR build time).
  return {
    schema: "smart-permissions.laya.v1",
    request: {
      tool: `${ir.provider}/${ir.toolName}`,
      capability: ir.capability,
      action: ir.action,
      workspace: ir.workspaceCwd,
      command: sanitize(ir.command ?? "", 1000),
      paths: ir.paths.slice(0, 10),
      hosts: ir.network?.hosts.slice(0, 10) ?? [],
      risk: ir.risk,
      riskReasons: ir.riskReasons.slice(0, 5),
      untrusted: ir.untrustedText.slice(0, 5),
    },
  };
}

export class HttpLayaClient implements LayaClient {
  readonly name = "laya.http";
  private consecutiveFailures = 0;
  private circuitOpenUntil = 0;

  constructor(private options: HttpLayaOptions) {}

  get circuitOpen(): boolean { return Date.now() < this.circuitOpenUntil; }
  get failures(): number { return this.consecutiveFailures; }

  private recordFailure(): void {
    this.consecutiveFailures += 1;
    if (this.consecutiveFailures >= 5) this.circuitOpenUntil = Date.now() + 60_000;
  }

  private recordSuccess(): void {
    this.consecutiveFailures = 0;
    this.circuitOpenUntil = 0;
  }

  async decide(ir: PermissionIR): Promise<LayaOutcome> {
    if (this.circuitOpen) {
      return { status: "failed", kind: "network", detail: "Laya circuit breaker open" };
    }
    const fetchImpl = this.options.fetchImpl ?? fetch;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.options.timeoutMs);
    try {
      const res = await fetchImpl(this.options.endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.options.token}`,
        },
        body: JSON.stringify(buildLayaPayload(ir)),
        signal: ctrl.signal,
      });
      if (!res.ok) {
        this.recordFailure();
        return { status: "failed", kind: "http", detail: `HTTP ${res.status}` };
      }
      const json: unknown = await res.json();
      const parsed = LAYA_VERDICT_SCHEMA.safeParse(json);
      if (!parsed.success) {
        this.recordFailure();
        return { status: "failed", kind: "invalid", detail: parsed.error.issues.map((i) => i.message).join("; ") };
      }
      this.recordSuccess();
      return { status: "ok", verdict: parsed.data };
    } catch (err) {
      this.recordFailure();
      if (err instanceof Error && err.name === "AbortError") {
        return { status: "failed", kind: "timeout", detail: `timeout after ${this.options.timeoutMs}ms` };
      }
      return { status: "failed", kind: "network", detail: err instanceof Error ? err.message : String(err) };
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Human-facing advisor naming.
 *  The engine reuses the LayaClient interface for Jev and composite advisors,
 *  so user-visible reason strings must attribute to the advisor that actually
 *  ran — never hardcode "Laya" (a Jev-only user would otherwise see "Laya …"
 *  and conclude the wrong provider decided). */
export function advisorDisplayNameFromRaw(raw: string): string {
  const n = (raw ?? "").toLowerCase();
  if (n.startsWith("jev")) return "Jev";
  if (n.startsWith("laya.http")) return "Laya";
  if (n.startsWith("advisory")) return "Jev+Laya";
  return "Advisor";
}

export function advisorDisplayName(client: LayaClient): string {
  const inner = (client as { inner?: readonly LayaClient[] }).inner;
  if (Array.isArray(inner) && inner.length > 0) {
    const parts = inner.map((c) => advisorDisplayNameFromRaw(c.name));
    const specific = [...new Set(parts)].filter((x) => x !== "Advisor");
    if (specific.length > 0) return specific.join("+");
    return "Advisor";
  }
  if (client.name === "advisory.composite") return "Jev+Laya";
  return advisorDisplayNameFromRaw(client.name);
}

/** Machine tag for matchedRules / fallback labels. Unknown stubs fall back to
 *  the historic "laya" value so existing rules/grep keep working. */
export function advisorTagFromRaw(raw: string): string {
  const n = (raw ?? "").toLowerCase();
  if (n.startsWith("jev")) return "jev";
  if (n.startsWith("laya.http")) return "laya";
  if (n.startsWith("advisory")) return "advisory";
  return "laya";
}

export function advisorTag(client: LayaClient): string {
  const inner = (client as { inner?: readonly LayaClient[] }).inner;
  if (Array.isArray(inner) && inner.length > 0) return "advisory";
  if (client.name === "advisory.composite") return "advisory";
  return advisorTagFromRaw(client.name);
}
