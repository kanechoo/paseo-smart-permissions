/** Smart Permissions monitor surface: stats + recent decisions + embedded settings.
 *  The whole dashboard is a single ScrollView so the settings section stays
 *  reachable no matter how many decision records pile up. SettingsPanel is
 *  embedded without its own ScrollView to avoid nested scrollers. */
import type { PluginSurfaceProps } from "@getpaseo/plugin/client";
import { useRpc, useSettings } from "@getpaseo/plugin/client";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Pressable, ScrollView, Text, View } from "react-native";
import { RecentRpc, StatsRpc } from "../shared/rpc.js";
import { SettingsPanel } from "./settings.js";
import { smartPermissionsSettings } from "../shared/settings-def.js";
import { resolveLang, t, type LangSetting } from "./i18n.js";
import { friendlyAdvisor, statsAdvisorLabel } from "./advisor-label.js";

const RECENT_COLLAPSED_COUNT = 8;

export function MonitorSurface({ theme, layout, host }: PluginSurfaceProps) {
  const callStats = useRpc(StatsRpc);
  const callRecent = useRpc(RecentRpc);
  const hostSettings = useSettings(smartPermissionsSettings);
  const lang = resolveLang(
    (hostSettings.status === "ready"
      ? (hostSettings.values as unknown as Record<string, unknown>).language
      : "system") as LangSetting | undefined,
  );
  const stats = useQuery({ queryKey: ["sp-stats"], queryFn: () => callStats({}), refetchInterval: 5000 });
  const recent = useQuery({ queryKey: ["sp-recent"], queryFn: () => callRecent({ limit: 30 }), refetchInterval: 5000 });
  const [refreshedAt, setRefreshedAt] = useState<string | null>(null);
  // Manual-press feedback only: background 5s auto-refetch must not flicker the button.
  const [manualRefreshing, setManualRefreshing] = useState(false);
  const [showAllRecent, setShowAllRecent] = useState(false);
  const styles = useMemo(() => ({
    screen: { flex: 1, backgroundColor: theme.colors.surface0 },
    content: { padding: layout.compact ? 16 : 24, paddingBottom: 48 },
    title: { color: theme.colors.foreground, fontSize: 18, fontWeight: "bold" as const, marginBottom: 8 },
    sectionTitle: { color: theme.colors.foreground, fontSize: 13, fontWeight: "bold" as const, letterSpacing: 0.5, textTransform: "uppercase" as const, marginTop: 20, marginBottom: 2 },
    card: { backgroundColor: theme.colors.surface1, borderWidth: 1, borderColor: theme.colors.border, borderRadius: 10, padding: 12, marginTop: 8 },
    row: { color: theme.colors.foreground, fontSize: 14, marginBottom: 4 },
    item: { paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: theme.colors.surface2 },
    small: { color: theme.colors.foreground, fontSize: 12 },
    muted: { color: theme.colors.foregroundMuted, fontSize: 12, marginTop: 4 },
    button: {
      alignSelf: "flex-start" as const, paddingVertical: 6, paddingHorizontal: 14,
      marginTop: 12,
      borderWidth: 1, borderColor: theme.colors.accent, borderRadius: 6,
      backgroundColor: "transparent",
    },
    buttonText: { color: theme.colors.accent, fontSize: 13 },
    refreshed: { color: theme.colors.foreground, fontSize: 12, opacity: 0.6, marginLeft: 8, alignSelf: "center" as const },
    buttonRow: { flexDirection: "row" as const, alignItems: "center" as const, marginTop: 4 },
    linkBtn: { marginTop: 8, alignSelf: "flex-start" as const },
    linkText: { color: theme.colors.accent, fontSize: 12 },
  }), [theme, layout.compact]);

  const entries = recent.data?.entries ?? [];
  const visibleEntries = showAllRecent ? entries : entries.slice(0, RECENT_COLLAPSED_COUNT);

  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content} showsVerticalScrollIndicator>
      <Text style={styles.title}>{t(lang, "app.title")}</Text>

      <Text style={styles.sectionTitle}>{t(lang, "sec.stats")}</Text>
      <View style={styles.card}>
        {stats.data ? (
          <Text style={styles.row}>
            {`enabled=${String(stats.data.enabled)} total=${stats.data.total} allow=${stats.data.allow} ask=${stats.data.ask} deny=${stats.data.deny} cache=${stats.data.cacheHits}/${stats.data.cacheMisses} learned=${stats.data.learnedRules} advisor=${statsAdvisorLabel(stats.data.laya, (stats.data as { advisor?: string }).advisor)}`}
          </Text>
        ) : <Text style={styles.row}>{t(lang, "stats.loading")}</Text>}
      </View>

      <Text style={styles.sectionTitle}>{t(lang, "sec.recent")}</Text>
      <View style={styles.card}>
        {visibleEntries.map((e) => {
          const via = friendlyAdvisor({ raw: null, display: (e as { advisor?: string }).advisor });
          const showVia = via === "Jev" || via === "Laya" || via === "Jev+Laya";
          return (
            <View key={`${e.requestId}-${e.timestamp}`} style={styles.item}>
              <Text style={styles.small}>{`[${e.finalDecision}] ${e.provider}/${e.action} risk=${e.risk} src=${e.decisionSource}${showVia ? ` via ${via}` : ""} · ${e.latencyMs}ms`}</Text>
              <Text style={styles.small}>{e.reason}</Text>
            </View>
          );
        })}
        {entries.length === 0 ? (
          <Text style={styles.muted}>{t(lang, "recent.empty")}</Text>
        ) : null}
        {entries.length > RECENT_COLLAPSED_COUNT ? (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={showAllRecent ? "collapse-recent" : "expand-recent"}
            style={styles.linkBtn}
            onPress={() => setShowAllRecent((v) => !v)}
          >
            <Text style={styles.linkText}>
              {showAllRecent
                ? t(lang, "recent.showLess")
                : `${t(lang, "recent.showMore")} (${entries.length})`}
            </Text>
          </Pressable>
        ) : null}
        <View style={styles.buttonRow}>
          <Pressable
            accessibilityRole="button" accessibilityLabel="Refresh"
            style={[styles.button, manualRefreshing ? { opacity: 0.5 } : null]}
            disabled={manualRefreshing}
            onPress={() => {
              if (manualRefreshing) return;
              setManualRefreshing(true);
              void Promise.all([stats.refetch(), recent.refetch()])
                .catch(() => undefined)
                .then(() => {
                  setRefreshedAt(new Date().toLocaleTimeString());
                  setManualRefreshing(false);
                });
            }}
          >
            <Text style={styles.buttonText}>
              {manualRefreshing ? `${t(lang, "action.refresh")}…` : t(lang, "action.refresh")}
            </Text>
          </Pressable>
          {refreshedAt ? (
            <Text style={styles.refreshed}>
              {`${t(lang, "action.refresh")}${lang === "zh" ? "于" : " at "}${refreshedAt}`}
            </Text>
          ) : null}
        </View>
      </View>

      <Text style={styles.sectionTitle}>{t(lang, "sec.settings")}</Text>
      <SettingsPanel theme={theme} layout={layout} host={host} embedded />
    </ScrollView>
  );
}
