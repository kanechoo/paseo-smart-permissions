/** Plugin settings schema (registerSettings) + defaults. */
import { z } from "zod";
export type UserRuleEffect = "allow" | "deny" | "ask";
export interface UserRule {
  id: string;
  effect: UserRuleEffect;
  provider?: string;
  capability?: string;
  commandPattern?: string;
  pathPattern?: string;
  hostPattern?: string;
  workspace?: string;
}

export const SETTINGS_ID = "smart-permissions-settings";
export const SETTINGS_VERSION = 3;

export const UserRuleSchema = z.object({
  id: z.string(),
  effect: z.enum(["allow", "deny", "ask"]),
  provider: z.string().optional(),
  capability: z.string().optional(),
  commandPattern: z.string().optional(),
  pathPattern: z.string().optional(),
  hostPattern: z.string().optional(),
  workspace: z.string().optional(),
});

export const SettingsSchema = z.object({
  enabled: z.boolean().default(true),
  language: z.enum(["zh", "en"]).default("en"),
  layaEnabled: z.boolean().default(false),
  layaEndpoint: z.string().default("http://127.0.0.1:17890/decide"),
  layaToken: z.string().default(""),
  layaTimeoutMs: z.number().int().min(1000).max(60000).default(15000),
  layaMinConfidence: z.number().min(0).max(1).default(0.6),
  jevEnabled: z.boolean().default(true),
  jevApiKey: z.string().default(""),
  jevModel: z.string().default("jev-1.13-free"),
  jevEndpoint: z.string().default("https://opencode.ai/zen/v1/systemone"),
  jevTimeoutMs: z.number().int().min(1000).max(60000).default(15000),
  jevMinConfidence: z.number().min(0).max(1).default(0.6),
  defaultPolicy: z.enum(["ask", "deny"]).default("ask"),
  cacheTtlSec: z.number().int().min(0).max(600).default(60),
  layaMaxConcurrency: z.number().int().min(1).max(16).default(4),
  learningEnabled: z.boolean().default(true),
  userRules: z.array(UserRuleSchema).default([]),
});

export type PluginSettings = z.infer<typeof SettingsSchema>;

export function parseSettings(input: unknown): PluginSettings {
  const raw = (input ?? {}) as Record<string, unknown>;
  // Pre-v3 stored "system" (or garbage): fold to the new default instead of
  // throwing, so old host values can never brick a save.
  const language = raw.language === "zh" || raw.language === "en" ? raw.language : "en";
  return SettingsSchema.parse({ ...raw, language });
}

export function defaultSettings(): PluginSettings {
  return SettingsSchema.parse({});
}

export function coerceUserRules(input: unknown): UserRule[] {
  const parsed = z.array(UserRuleSchema).safeParse(input ?? []);
  if (!parsed.success) return [];
  return parsed.data;
}

/** Closed value sets derived from the engine: providers normalize to lowercase
 *  families (see normalizeProviderFamily), capabilities to the IR union. Anything
 *  else in a rule never matches a real request — a silent dead rule. */
const KNOWN_PROVIDERS = ["pi", "opencode", "codex", "claude", "generic", "*"];
const KNOWN_CAPABILITIES = [
  "file.read", "file.write", "file.delete", "file.exec", "shell.exec",
  "network.egress", "process", "env.read", "git.read", "git.write",
  "git.destructive", "secret.access", "system.config", "other", "unknown", "*",
];

function knownValueIssue(kind: "provider" | "capability", value: string, known: string[]): string | null {
  if (known.includes(value)) return null;
  const lower = value.toLowerCase();
  if (lower !== value && known.includes(lower)) {
    return `${kind}: ${JSON.stringify(value)} never matches — did you mean ${JSON.stringify(lower)}? (known: ${known.join(", ")})`;
  }
  return `${kind}: ${JSON.stringify(value)} never matches a real request (known: ${known.join(", ")})`;
}

/** An allow/ask rule with zero effective conditions matches every request
 *  (auto-allow-all / ask-everything). `"*"` counts as absent, not as a
 *  condition — otherwise { effect: "allow", provider: "*" } would slip through
 *  the guard and match everything. Deny rules are fail-closed and exempt. */
export function ruleHasCondition(rule: Pick<UserRule, "provider" | "capability" | "commandPattern" | "pathPattern" | "hostPattern" | "workspace">): boolean {
  const substantive = (v: string | undefined) => !!v && v !== "*";
  return Boolean(
    substantive(rule.provider) || substantive(rule.capability) ||
    rule.commandPattern || rule.pathPattern || rule.hostPattern || rule.workspace,
  );
}

export interface UserRuleIssue { index: number; messages: string[]; }

/** commandPattern is substring match, or /regex/ when wrapped in slashes
 *  (see matchUserRule). Two shapes are almost certainly mistakes, so they are
 *  reported as issues instead of silently saving a dead or crashing rule:
 *  - `*` / `?` outside /regex/ are matched LITERALLY, not as wildcards
 *    (`kubectl get *` never matches `kubectl get pods`);
 *  - an invalid /regex/ would throw inside the engine at match time. */
function commandPatternIssue(pattern: string): string | null {
  const isRegex = pattern.startsWith("/") && pattern.endsWith("/") && pattern.length > 2;
  if (isRegex) {
    try {
      new RegExp(pattern.slice(1, -1), "i");
    } catch (e) {
      return `commandPattern: invalid regex ${pattern} (${e instanceof Error ? e.message : String(e)})`;
    }
    return null;
  }
  if (/[*?]/.test(pattern)) {
    const base = pattern.replace(/[*?]+/g, " ").replace(/\s+/g, " ").trim();
    const hint = base ? ` — did you mean substring "${base}" or regex /${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}.*/?` : "";
    return `commandPattern: ${JSON.stringify(pattern)} matches '*' and '?' literally, not as wildcards${hint}`;
  }
  if (pattern !== "" && pattern.trim() === "") {
    return `commandPattern: blank pattern matches almost every command; add a real substring or delete the rule`;
  }
  return null;
}

/** Strict per-rule validation for the settings editor.
 *  Returns clean rules plus indexed issues; the caller decides (the editor
 *  rejects the whole save so one bad rule can never pollute stored rules). */
export function validateUserRules(input: unknown): { rules: UserRule[]; issues: UserRuleIssue[] } {
  const list = Array.isArray(input) ? input : [];
  const rules: UserRule[] = [];
  const issues: UserRuleIssue[] = [];
  const seenIds = new Map<string, number>();
  list.forEach((item, index) => {
    const parsed = UserRuleSchema.safeParse(item);
    if (!parsed.success) {
      issues.push({ index, messages: parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`) });
      return;
    }
    const r = parsed.data;
    const msgs: string[] = [];
    if (r.id.trim() === "") msgs.push(`id: must not be blank`);
    else if (seenIds.has(r.id)) msgs.push(`id: ${JSON.stringify(r.id)} duplicates rule #${(seenIds.get(r.id) ?? 0) + 1} — ids must be unique (bulk delete would remove both)`);
    else seenIds.set(r.id, index);
    if (r.provider !== undefined) {
      const m = knownValueIssue("provider", r.provider, KNOWN_PROVIDERS);
      if (m) msgs.push(m);
    }
    if (r.capability !== undefined) {
      const m = knownValueIssue("capability", r.capability, KNOWN_CAPABILITIES);
      if (m) msgs.push(m);
    }
    if (r.commandPattern !== undefined) {
      const m = commandPatternIssue(r.commandPattern);
      if (m) msgs.push(m);
    }
    if (r.pathPattern !== undefined && r.pathPattern !== "" && r.pathPattern.trim() === "") {
      msgs.push(`pathPattern: blank pattern never matches; use a glob like "src/**" or remove it`);
    }
    if (r.hostPattern !== undefined && r.hostPattern !== "") {
      if (r.hostPattern.trim() === "") msgs.push(`hostPattern: blank pattern never matches; use a bare hostname like "example.com" or remove it`);
      // Hosts are bare names from URL parsing — scheme/path/port can never match.
      else if (/[:/\s]/.test(r.hostPattern)) msgs.push(`hostPattern: ${JSON.stringify(r.hostPattern)} never matches — hosts are bare names like "example.com" (no scheme, path, or port)`);
    }
    if (r.workspace !== undefined && r.workspace !== "") {
      if (r.workspace.startsWith("~")) msgs.push(`workspace: ${JSON.stringify(r.workspace)} never matches — use the absolute path (agent working directories never start with ~)`);
      else if (!r.workspace.startsWith("/")) msgs.push(`workspace: ${JSON.stringify(r.workspace)} never matches — must be absolute (agent working directories are absolute paths)`);
    }
    if ((r.effect === "allow" || r.effect === "ask") && !ruleHasCondition(r)) {
      msgs.push(`${r.effect} rules need at least one match condition, otherwise they would match everything`);
    }
    if (msgs.length > 0) issues.push({ index, messages: msgs });
    else rules.push(r);
  });
  return { rules, issues };
}
