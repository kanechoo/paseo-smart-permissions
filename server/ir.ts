/** Unified Permission IR. The decision engine consumes ONLY this. */
import type { AgentPermissionRequest, ToolCallDetail } from "@getpaseo/protocol/agent-types";
import { analyzeCommand, isKnownSafeCommand } from "./commands.js";
import { classifyPaths } from "./paths.js";
import { sanitize } from "./redact.js";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Capability =
  | "file.read" | "file.write" | "file.delete" | "file.exec"
  | "shell.exec" | "network.egress" | "process" | "env.read"
  | "git.read" | "git.write" | "git.destructive"
  | "secret.access" | "system.config" | "other" | "unknown";

export interface NetworkTarget { urls: string[]; hosts: string[]; }

export interface PermissionIR {
  requestId: string;
  provider: string;       // normalized family: pi|opencode|codex|claude|generic
  providerRaw: string;
  agentId: string;
  workspaceId: string | null;
  workspaceCwd: string;
  kind: string;
  toolName: string;
  title: string;
  description: string;
  capability: Capability;
  action: string;
  command?: string;
  commandCwd?: string;
  paths: string[];
  network?: NetworkTarget;
  envAccess: string[];
  rawSummary: string;     // sanitized, safe for Laya/logs
  untrustedText: string[];// attacker-controllable strings (isolated)
  risk: RiskLevel;
  riskReasons: string[];
}

export function normalizeProviderFamily(raw: string, fallback?: string): string {
  const src = `${raw} ${fallback ?? ""}`.toLowerCase();
  if (/\bpi\b/.test(src) || src.includes("pi/") || src.startsWith("pi")) return "pi";
  if (src.includes("opencode")) return "opencode";
  if (src.includes("codex")) return "codex";
  if (src.includes("claude")) return "claude";
  return "generic";
}

const RISK_ORDER: RiskLevel[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
export function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER[Math.max(RISK_ORDER.indexOf(a), RISK_ORDER.indexOf(b))];
}

function hostOf(url: string): string | null {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch { return null; }
}

function isLocalHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".localhost");
}

function isLanHost(host: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(host);
}

export function rateNetwork(urls: string[]): { risk: RiskLevel; reasons: string[]; hosts: string[] } {
  const hosts = urls.map(hostOf).filter((h): h is string => h !== null);
  const reasons: string[] = [];
  let risk: RiskLevel = "LOW";
  for (const h of hosts) {
    if (isLocalHost(h)) { risk = maxRisk(risk, "LOW"); reasons.push(`localhost egress: ${h}`); }
    else if (isLanHost(h)) { risk = maxRisk(risk, "MEDIUM"); reasons.push(`LAN egress: ${h}`); }
    else { risk = maxRisk(risk, "HIGH"); reasons.push(`public egress: ${h}`); }
  }
  return { risk, reasons, hosts };
}

export interface BuildInput {
  request: AgentPermissionRequest;
  agent: { id: string; provider: string; cwd: string; workspaceId: string | null };
}

/** Build the IR from a Paseo-normalized permission request. */
export function buildIR({ request, agent }: BuildInput): PermissionIR {
  const maybeDetail = request.detail as ToolCallDetail | undefined;
  const provider = normalizeProviderFamily(request.provider, agent.provider);
  let capability: Capability = "unknown";
  let action = `tool.${request.name}`;
  let command: string | undefined;
  let commandCwd: string | undefined;
  let paths: string[] = [];
  let network: NetworkTarget | undefined;
  let envAccess: string[] = [];
  let risk: RiskLevel = "MEDIUM";
  const riskReasons: string[] = [];
  const untrustedText: string[] = [];
  const raise = (r: RiskLevel, why: string) => { risk = maxRisk(risk, r); riskReasons.push(why); };

  // Missing detail: conservative unknown baseline; input补强 below may refine it.
  const detail: ToolCallDetail = maybeDetail ?? { type: "unknown", input: {}, output: {} };
  const t = detail.type;
  if (t === "shell") {
    capability = "shell.exec"; action = "shell.exec";
    command = detail.command; commandCwd = detail.cwd;
    untrustedText.push(detail.command);
    const a = analyzeCommand(detail.command);
    if (a.danger === "CRITICAL") raise("CRITICAL", `dangerous command: ${a.dangerReasons.join(", ")}`);
    else if (a.danger === "HIGH") raise("HIGH", `risky command: ${a.dangerReasons.join(", ")}`);
    else if (isKnownSafeCommand(detail.command)) { risk = "LOW"; riskReasons.push("known-safe command baseline"); }
    else raise("MEDIUM", "shell execution");
  } else if (t === "read") {
    capability = "file.read"; action = "file.read"; paths = [detail.filePath];
    risk = "LOW"; riskReasons.push("workspace-scoped read baseline");
  } else if (t === "edit" || t === "write") {
    capability = "file.write"; action = detail.type === "edit" ? "file.edit" : "file.write";
    paths = [detail.filePath];
    if (detail.type === "write" && typeof detail.content === "string") untrustedText.push(detail.content.slice(0, 2000));
    else if (detail.type === "edit" && typeof detail.newString === "string") untrustedText.push(detail.newString.slice(0, 2000));
    risk = "LOW"; riskReasons.push("workspace-scoped write baseline");
  } else if (t === "search") {
    if (detail.toolName === "web_search") {
      capability = "network.egress"; action = "search.web";
      raise("MEDIUM", "web search egress");
    } else { capability = "file.read"; action = "search.local"; risk = "LOW"; riskReasons.push("local search"); }
    untrustedText.push(detail.query);
  } else if (t === "fetch") {
    capability = "network.egress"; action = "network.fetch";
    risk = "LOW"; riskReasons.push("fetch baseline");
    const rated = rateNetwork([detail.url]);
    network = { urls: [detail.url], hosts: rated.hosts };
    raise(rated.risk, rated.reasons.join("; ") || "fetch egress");
    untrustedText.push(detail.url);
  } else if (t === "worktree_setup") {
    capability = "git.write"; action = "git.worktree_setup"; paths = [detail.worktreePath];
    raise("HIGH", "worktree setup runs commands");
  } else if (t === "sub_agent") {
    capability = "unknown"; action = "agent.sub_agent"; risk = "MEDIUM"; riskReasons.push("sub-agent delegation");
    if (detail.description) untrustedText.push(detail.description);
  } else if (t === "plan" || t === "plain_text") {
    capability = "other"; action = detail.type; risk = "LOW"; riskReasons.push("display-only content");
    untrustedText.push(detail.type === "plan" ? detail.text : (detail.text ?? detail.label ?? ""));
  } else {
    // "unknown" detail or missing: try name/input補强 (adapter layer does deep parse;
    // here keep conservative defaults).
    capability = "unknown"; action = `tool.${request.name}`;
    risk = "MEDIUM"; riskReasons.push("unclassified tool call");
  }

  // Path security overlay (can only raise).
  if (paths.length > 0) {
    const c = classifyPaths(agent.cwd, paths);
    if (c.secretFile) raise("CRITICAL", c.reasons.filter((r) => r.startsWith("secret")).join("; "));
    if (c.sensitive) raise("CRITICAL", c.reasons.filter((r) => r.startsWith("sensitive")).join("; "));
    if (c.symlinkEscape) raise("CRITICAL", c.reasons.filter((r) => r.startsWith("symlink")).join("; "));
    if (c.escape) raise("HIGH", c.reasons.filter((r) => r.startsWith("path escapes")).join("; "));
    if (c.unresolvable) raise("HIGH", c.reasons.filter((r) => r.startsWith("symlink-unresolvable")).join("; "));
    if ((capability as string) === "file.delete" || /delete|remove|unlink/.test(action)) raise("HIGH", "delete operation");
  }

  // input/metadata補强: extract paths/command/url hints when detail was unknown.
  const input = (request.input ?? {}) as Record<string, unknown>;
  if (capability === "unknown") {
    const maybeCmd = [input["command"], input["cmd"]].find((v) => typeof v === "string") as string | undefined;
    const maybePath = [input["filePath"], input["path"], input["file"]].find((v) => typeof v === "string") as string | undefined;
    const maybeUrl = [input["url"]].find((v) => typeof v === "string") as string | undefined;
    const nm = request.name.toLowerCase();
    if (maybeCmd || /bash|exec|shell|command/.test(nm)) {
      capability = "shell.exec"; action = "shell.exec"; command = maybeCmd ?? request.name;
      if (command) { const a = analyzeCommand(command); if (a.danger !== "NONE") raise(a.danger === "CRITICAL" ? "CRITICAL" : "HIGH", a.dangerReasons.join(", ")); }
      if (command && isKnownSafeCommand(command)) { risk = "LOW"; riskReasons.push("known-safe command baseline"); }
      else raise("MEDIUM", "shell-like tool via name/input");
    } else if (maybePath) {
      capability = /read|cat/.test(nm) ? "file.read" : "file.write"; action = capability; paths = [maybePath];
      const c = classifyPaths(agent.cwd, paths);
      if (c.secretFile || c.sensitive || c.symlinkEscape) raise("CRITICAL", c.reasons.join("; "));
      else if (c.escape || c.unresolvable) raise("HIGH", c.reasons.join("; "));
    } else if (maybeUrl) {
      capability = "network.egress"; action = "network.fetch";
      const rated = rateNetwork([maybeUrl]); network = { urls: [maybeUrl], hosts: rated.hosts };
      raise(rated.risk, rated.reasons.join("; "));
    }
  }

  const summaryParts = [
    `${provider}/${request.name}`,
    `cap=${capability}`,
    command ? `cmd=${command.slice(0, 200)}` : "",
    paths.length ? `paths=${paths.slice(0, 5).join(",")}` : "",
    network?.urls?.length ? `urls=${network.urls.slice(0, 3).join(",")}` : "",
  ].filter(Boolean);

  return {
    requestId: request.id,
    provider,
    providerRaw: request.provider,
    agentId: agent.id,
    workspaceId: agent.workspaceId,
    workspaceCwd: agent.cwd,
    kind: request.kind,
    toolName: request.name,
    title: request.title ?? "",
    description: request.description ?? "",
    capability,
    action,
    command,
    commandCwd,
    paths,
    network,
    envAccess,
    rawSummary: sanitize(summaryParts.join(" "), 1000),
    untrustedText: untrustedText.map((s) => sanitize(s, 2000)),
    risk,
    riskReasons,
  };
}
