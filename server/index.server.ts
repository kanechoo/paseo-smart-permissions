/** Paseo plugin server entry: hooks permission events to the decision engine. */
import type { PluginServerContext } from "@getpaseo/plugin/server";
import { SmartPermissionsService } from "./service.js";
import { advisorDisplayNameFromRaw } from "./laya.js";
import { smartPermissionsSettings } from "../shared/settings-def.js";
import {
  ConfigGetRpc, ConfigUpdateRpc, PreviewRpc, RecentRpc, StatsRpc,
} from "../shared/rpc.js";

const service = new SmartPermissionsService();

export default function contribute(server: PluginServerContext) {
  server.registerSettings(smartPermissionsSettings);

  server.handle(StatsRpc, () => service.stats());
  server.handle(RecentRpc, ({ limit }) => ({
    entries: service.audit.recent(limit).map((e) => ({
      timestamp: e.timestamp,
      requestId: e.requestId,
      provider: e.provider,
      capability: e.capability,
      action: e.action,
      target: e.target,
      risk: e.risk,
      finalDecision: e.finalDecision,
      decisionSource: e.decisionSource,
      reason: e.reason,
      fallback: e.fallback,
      latencyMs: e.latencyMs,
      advisor: advisorDisplayNameFromRaw(e.laya),
    })),
  }));
  server.handle(PreviewRpc, async (input) => {
    const d = await service.preview(input);
    return {
      decision: d.decision, source: d.source, reason: d.reason,
      risk: d.risk, matchedRules: d.matchedRules,
    };
  });
  server.handle(ConfigGetRpc, () => ({ settings: service.settings as unknown as Record<string, unknown> }));
  server.handle(ConfigUpdateRpc, (input) => {
    const error = service.applySettings(input.settings);
    if (error) return { ok: false as const, error };
    return { ok: true as const, rulesVersion: service.rulesVersion };
  });

  // Observe-only hook; auto-decisions go through respondToPermission.
  // ASK = intentionally no respond call (request stays pending in native UI).
  const offRequested = server.on("agent.permission_requested", async (event, context) => {
    try {
      await service.onPermissionRequested(
        event.request,
        {
          id: event.agent.id,
          provider: event.agent.provider,
          cwd: event.agent.cwd,
          workspaceId: event.agent.workspaceId,
        },
        async (agentId, requestId, response) => {
          // PaseoApi has no top-level respond; the handle-based API is canonical.
          await context.paseo.agents.ref(agentId).respondToPermission({ requestId, response });
        },
      );
    } catch {
      // Never break the agent turn on plugin errors: leave pending (ASK).
    }
  });
  const offResolved = server.on("agent.permission_resolved", (event) => {
    try {
      service.onPermissionResolved(event.requestId, event.resolution);
    } catch { /* learning must never throw */ }
  });

  return () => { offRequested(); offResolved(); };
}
