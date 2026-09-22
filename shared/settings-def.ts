/** Shared settings definition (server registerSettings + client useSettings). */
import { defineSettings } from "@getpaseo/plugin";
import { SETTINGS_ID, SETTINGS_VERSION, SettingsSchema, parseSettings, validateUserRules, type PluginSettings } from "./config.js";
export { ruleHasCondition } from "./config.js";

/** v1 -> v2: cache TTL was milliseconds (cacheTtlMs), now seconds (cacheTtlSec).
 *  Rounds to the nearest second; unknown shapes fall through untouched. */
export function migrateSettings(values: unknown): unknown {
  if (!values || typeof values !== "object") return values ?? {};
  const v = { ...(values as Record<string, unknown>) };
  if (typeof v.cacheTtlMs === "number") {
    if (v.cacheTtlSec === undefined) v.cacheTtlSec = Math.max(0, Math.round(v.cacheTtlMs / 1000));
    delete v.cacheTtlMs;
  }
  return v;
}

export const smartPermissionsSettings = defineSettings({
  id: SETTINGS_ID,
  scope: "host",
  version: SETTINGS_VERSION,
  schema: SettingsSchema,
  migrate: migrateSettings,
});

/** Draft coercion for the in-surface settings editor (pure, unit-tested).
 *  Text inputs arrive as strings; invalid numerics fall back to `base`
 *  (the editor never bricks the engine with NaN). Unknown keys ignored. */
export function applySettingsDraft(
  base: PluginSettings,
  text: Record<string, string>,
  toggles: Record<string, boolean>,
  rules?: unknown,
): PluginSettings {
  const next: Record<string, unknown> = { ...base };
  const strKeys = ["jevApiKey", "jevModel", "jevEndpoint", "layaEndpoint", "layaToken"] as const;
  const intKeys = ["jevTimeoutMs", "layaTimeoutMs", "cacheTtlSec", "layaMaxConcurrency"] as const;
  const floatKeys = ["jevMinConfidence", "layaMinConfidence"] as const;
  const boolKeys = ["enabled", "jevEnabled", "layaEnabled", "learningEnabled"] as const;
  for (const k of strKeys) if (text[k] !== undefined) next[k] = text[k];
  for (const k of intKeys) {
    if (text[k] === undefined) continue;
    const n = Number.parseInt(text[k], 10);
    if (Number.isInteger(n)) next[k] = n;
  }
  for (const k of floatKeys) {
    if (text[k] === undefined) continue;
    const n = Number.parseFloat(text[k]);
    if (Number.isFinite(n)) next[k] = n;
  }
  for (const k of boolKeys) if (toggles[k] !== undefined) next[k] = toggles[k];
  if (text.defaultPolicy === "ask" || text.defaultPolicy === "deny") next.defaultPolicy = text.defaultPolicy;
  if (text.language === "system" || text.language === "zh" || text.language === "en") next.language = text.language;
  if (rules !== undefined) {
    const { rules: clean, issues } = validateUserRules(rules);
    if (issues.length > 0) {
      const detail = issues.map((i) => `rule #${i.index + 1}: ${i.messages.join("; ")}`).join(" | ");
      throw new Error(`invalid user rules (${detail})`);
    }
    next.userRules = clean;
  }
  return parseSettings(next);}

/** Editor guard for allow-all / ask-everything shapes (single definition lives
 *  in shared/config.ts so save-time validation enforces the same rule). */
