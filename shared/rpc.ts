/** Plugin RPC contracts (server.handle + client useRpc). */
import { defineRpc } from "@getpaseo/plugin";
import { z } from "zod";

export const StatsRpc = defineRpc({
  name: "smart-permissions.stats",
  input: z.object({}),
  output: z.object({
    enabled: z.boolean(),
    total: z.number(),
    allow: z.number(),
    ask: z.number(),
    deny: z.number(),
    cacheHits: z.number(),
    cacheMisses: z.number(),
    cacheSize: z.number(),
    learnedRules: z.number(),
    rulesVersion: z.number(),
    laya: z.string(),
    advisor: z.string().optional(),
  }),
});

export const RecentRpc = defineRpc({
  name: "smart-permissions.recent",
  input: z.object({ limit: z.number().int().min(1).max(200).default(50) }),
  output: z.object({
    entries: z.array(z.object({
      timestamp: z.string(),
      requestId: z.string(),
      provider: z.string(),
      capability: z.string(),
      action: z.string(),
      target: z.string(),
      risk: z.string(),
      finalDecision: z.string(),
      decisionSource: z.string(),
      reason: z.string(),
      fallback: z.boolean(),
      latencyMs: z.number(),
      advisor: z.string().optional(),
    })),
  }),
});

export const PreviewRpc = defineRpc({
  name: "smart-permissions.preview",
  input: z.object({
    provider: z.string().default("opencode"),
    toolName: z.string().default("Bash"),
    kind: z.enum(["tool", "plan", "question", "mode", "other"]).default("tool"),
    cwd: z.string(),
    command: z.string().optional(),
    filePath: z.string().optional(),
    url: z.string().optional(),
  }),
  output: z.object({
    decision: z.string(),
    source: z.string(),
    reason: z.string(),
    risk: z.string(),
    matchedRules: z.array(z.string()),
  }),
});

export const ConfigGetRpc = defineRpc({
  name: "smart-permissions.config.get",
  input: z.object({}),
  output: z.object({ settings: z.record(z.string(), z.unknown()) }),
});

export const ConfigUpdateRpc = defineRpc({
  name: "smart-permissions.config.update",
  input: z.object({ settings: z.record(z.string(), z.unknown()) }),
  output: z.object({ ok: z.boolean(), error: z.string().optional(), rulesVersion: z.number().optional() }),
});
