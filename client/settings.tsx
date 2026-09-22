/** In-surface settings editor: host-persisted values + live-apply to the engine.
 *  Source of truth is the host settings store (useSettings); Save writes there
 *  and then pushes the same document through ConfigUpdateRpc so the running
 *  engine applies it without a plugin reload. On first mount the panel also
 *  reconciles the server once (covers daemon restarts: the server boots from
 *  code defaults, the store holds the user's saved values). */
import { useEffect, useMemo, useRef, useState } from "react";
import { Pressable, ScrollView, Switch, Text, TextInput, View } from "react-native";
import { useRpc, useSettings } from "@getpaseo/plugin/client";
import type { PluginSurfaceProps } from "@getpaseo/plugin/client";
import { useQuery } from "@tanstack/react-query";
import { coerceUserRules, validateUserRules, type PluginSettings, type UserRule } from "../shared/config.js";
import { ConfigUpdateRpc, StatsRpc } from "../shared/rpc.js";
import { applySettingsDraft, ruleHasCondition, smartPermissionsSettings } from "../shared/settings-def.js";
import { resolveLang, t, type Lang } from "./i18n.js";
import { friendlyAdvisor } from "./advisor-label.js";

type Draft = { text: Record<string, string>; toggles: Record<string, boolean>; rules: UserRule[] };

const TEXT_KEYS = [
  "jevApiKey", "jevModel", "jevEndpoint", "jevTimeoutMs", "jevMinConfidence",
  "layaEndpoint", "layaToken", "layaTimeoutMs", "layaMinConfidence",
  "cacheTtlSec", "layaMaxConcurrency", "language",
] as const;
const BOOL_KEYS = ["enabled", "jevEnabled", "layaEnabled", "learningEnabled"] as const;

function seed(values: PluginSettings): Draft {
  const rec = values as unknown as Record<string, unknown>;
  const text: Record<string, string> = { defaultPolicy: String(rec.defaultPolicy ?? "ask") };
  for (const k of TEXT_KEYS) text[k] = String(rec[k] ?? (k === "language" ? "en" : ""));
  const toggles: Record<string, boolean> = {};
  for (const k of BOOL_KEYS) toggles[k] = Boolean(rec[k]);
  return { text, toggles, rules: coerceUserRules(rec.userRules) };
}

function same(a: Draft, b: Draft): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function SettingsPanel({ theme, layout, embedded, onPreviewLanguage }: PluginSurfaceProps & { embedded?: boolean; onPreviewLanguage?: (lang: Lang | undefined) => void }) {
  const c = theme.colors;
  const settings = useSettings(smartPermissionsSettings);
  const callUpdate = useRpc(ConfigUpdateRpc);
  const callStats = useRpc(StatsRpc);
  const live = useQuery({ queryKey: ["sp-settings-live"], queryFn: () => callStats({}), refetchInterval: 5000 });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saved, setSaved] = useState<Draft | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [showSecrets, setShowSecrets] = useState(false);
  const [newEffect, setNewEffect] = useState<"allow" | "deny" | "ask">("allow");
  const [newCond, setNewCond] = useState<Record<string, string>>({
    provider: "", capability: "", commandPattern: "", pathPattern: "", hostPattern: "", workspace: "",
  });
  const [addRuleError, setAddRuleError] = useState<string | null>(null);
  const idRef = useRef(0);
  const syncedRef = useRef(false);

  const readyValues = settings.status === "ready" ? (settings.values as PluginSettings) : null;
  useEffect(() => {
    if (readyValues && draft === null) {
      const s = seed(readyValues);
      setDraft(s);
      setSaved(s);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readyValues]);

  // One-shot reconcile: server boots from code defaults; push stored values once.
  useEffect(() => {
    if (settings.status !== "ready" || syncedRef.current) return;
    syncedRef.current = true;
    callUpdate({ settings: settings.values as unknown as Record<string, unknown> }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.status]);

  const lang = resolveLang(draft?.text.language);

  const compact = layout?.compact === true;
  const ruleCellWidth = compact ? "100%" : "50%";

  // Let an embedding surface (dashboard) preview the draft language before save.
  const draftLang = (draft?.text.language === "zh" || draft?.text.language === "en" ? draft.text.language : undefined) as Lang | undefined;
  useEffect(() => {
    onPreviewLanguage?.(draftLang);
  }, [draftLang, onPreviewLanguage]);

  const s = useMemo(() => ({
    wrap: { paddingBottom: 32 },
    banner: { backgroundColor: c.surface1, borderWidth: 1, borderColor: c.border, borderRadius: 10, padding: 12, marginBottom: 4 },
    bannerTitle: { color: c.foreground, fontSize: 14, fontWeight: "bold" as const },
    bannerSub: { color: c.foregroundMuted, fontSize: 12, marginTop: 2 },
    section: { marginTop: 18 },
    sectionTitle: { color: c.foreground, fontSize: 13, fontWeight: "bold" as const, letterSpacing: 0.5, textTransform: "uppercase" as const, marginBottom: 2 },
    card: { backgroundColor: c.surface1, borderWidth: 1, borderColor: c.border, borderRadius: 10, padding: 12, marginTop: 8 },
    label: { color: c.foreground, fontSize: 14, fontWeight: "600" as const },
    desc: { color: c.foregroundMuted, fontSize: 12, marginTop: 2, lineHeight: 16 },
    input: { color: c.foreground, fontSize: 13, backgroundColor: c.surface0, borderWidth: 1, borderColor: c.border, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 8, marginTop: 8 },
    segRow: { flexDirection: "row" as const, marginTop: 8, backgroundColor: c.surface0, borderWidth: 1, borderColor: c.border, borderRadius: 8, overflow: "hidden" as const },
    segOpt: { flex: 1, paddingVertical: 8, alignItems: "center" as const },
    segOptText: { fontSize: 13 },
    fieldGap: { marginTop: 14 },
    switchRow: { flexDirection: "row" as const, alignItems: "center" as const, justifyContent: "space-between" as const },
    switchText: { flex: 1, paddingRight: 12 },
    saveBtn: { marginTop: 18, backgroundColor: c.surface2, borderWidth: 1, borderColor: c.border, borderRadius: 10, paddingVertical: 12, alignItems: "center" as const, opacity: 1 },
    saveBtnDisabled: { opacity: 0.5 },
    saveText: { color: c.foreground, fontSize: 15, fontWeight: "bold" as const },
    msgOk: { color: c.statusSuccess, fontSize: 12, marginTop: 8 },
    msgErr: { color: c.statusDanger, fontSize: 12, marginTop: 8 },
    dirty: { color: c.statusWarning, fontSize: 12, marginTop: 8 },
    linkBtn: { marginTop: 6 },
    linkText: { color: c.foreground, fontSize: 12, textDecorationLine: "underline" as const },
    rulesGrid: { flexDirection: "row" as const, flexWrap: "wrap" as const, marginHorizontal: -4, marginTop: 4 },
    ruleCell: { paddingHorizontal: 4, marginTop: 8 },
    ruleCard: { flex: 1, backgroundColor: c.surface0, borderWidth: 1, borderColor: c.border, borderRadius: 8, padding: 10 },
    ruleHead: { flexDirection: "row" as const, alignItems: "center" as const, justifyContent: "space-between" as const },
    badgeAllow: { borderWidth: 1, borderColor: c.statusSuccess, borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3 },
    badgeAsk: { borderWidth: 1, borderColor: c.statusWarning, borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3 },
    badgeDeny: { borderWidth: 1, borderColor: c.statusDanger, borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3 },
    badgeText: { fontSize: 12, fontWeight: "bold" as const },
    ruleSummary: { color: c.foreground, fontSize: 12, marginTop: 6, lineHeight: 17 },
    deleteBtn: { paddingHorizontal: 8, paddingVertical: 6 },
    deleteText: { color: c.statusDanger, fontSize: 12 },
    addBtn: { marginTop: 12, backgroundColor: c.surface0, borderWidth: 1, borderColor: c.border, borderRadius: 8, paddingVertical: 9, alignItems: "center" as const },
    addText: { color: c.foreground, fontSize: 14, fontWeight: "600" as const },
  }), [c]);

  if (settings.status === "loading" || !draft) {
    return <View><Text style={s.bannerSub}>{t(lang, "settings.loading")}</Text></View>;
  }
  if (settings.status === "error" || settings.status === "invalid") {
    return <View><Text style={s.msgErr}>{`${t(lang, "settings.unavailable")}${settings.error}`}</Text></View>;
  }

  const setText = (k: string) => (v: string) =>
    setDraft((d) => (d ? { ...d, text: { ...d.text, [k]: v } } : d));
  const setToggle = (k: string, v: boolean) =>
    setDraft((d) => (d ? { ...d, toggles: { ...d.toggles, [k]: v } } : d));
  const dirty = saved ? !same(draft, saved) : false;

  const seg = (value: string, options: Array<{ v: string; label: string }>, onPick: (v: string) => void, labelPrefix: string) => (
    <View style={s.segRow}>
      {options.map((o) => {
        const active = o.v === value;
        return (
          <Pressable
            key={o.v} accessibilityRole="button" accessibilityLabel={`${labelPrefix}-${o.v}`}
            style={[s.segOpt, active ? { backgroundColor: c.surface2 } : null]}
            onPress={() => onPick(o.v)}
          >
            <Text style={[s.segOptText, { color: active ? c.foreground : c.foregroundMuted, fontWeight: active ? "600" as const : "400" as const }]}>
              {o.label}
            </Text>
          </Pressable>
        );
      })}
    </View>
  );

  const boolField = (key: string, label: string, desc: string) => (
    <View style={s.switchRow}>
      <View style={s.switchText}>
        <Text style={s.label}>{label}</Text>
        <Text style={s.desc}>{desc}</Text>
      </View>
      <Switch
        accessibilityLabel={`toggle-${key}`}
        value={draft.toggles[key] === true}
        onValueChange={(v) => setToggle(key, v)}
        trackColor={{ false: c.surface2, true: c.foregroundMuted }}
        thumbColor={draft.toggles[key] ? c.foreground : c.foregroundMuted}
      />
    </View>
  );

  const textField = (key: string, label: string, desc: string, secret = false, placeholder = "") => (
    <View style={s.fieldGap}>
      <Text style={s.label}>{label}</Text>
      <Text style={s.desc}>{desc}</Text>
      <TextInput
        style={s.input}
        value={draft.text[key] ?? ""}
        onChangeText={setText(key)}
        placeholder={placeholder}
        secureTextEntry={secret && !showSecrets}
        autoCapitalize="none"
        autoCorrect={false}
      />
    </View>
  );

  const summarizeRule = (r: UserRule): string => {
    const parts: string[] = [];
    if (r.provider) parts.push(`provider=${r.provider}`);
    if (r.capability) parts.push(`capability=${r.capability}`);
    if (r.commandPattern) parts.push(`command~${r.commandPattern}`);
    if (r.pathPattern) parts.push(`path=${r.pathPattern}`);
    if (r.hostPattern) parts.push(`host~${r.hostPattern}`);
    if (r.workspace) parts.push(`workspace=${r.workspace}`);
    return parts.length > 0 ? parts.join(" · ") : t(lang, "rules.any");
  };

  const addRule = () => {
    const trim = (v: string) => v.trim();
    const candidate = {
      provider: trim(newCond.provider ?? ""),
      capability: trim(newCond.capability ?? ""),
      commandPattern: trim(newCond.commandPattern ?? ""),
      pathPattern: trim(newCond.pathPattern ?? ""),
      hostPattern: trim(newCond.hostPattern ?? ""),
      workspace: trim(newCond.workspace ?? ""),
    };
    if ((newEffect === "allow" || newEffect === "ask") && !ruleHasCondition(candidate)) {
      setAddRuleError(t(lang, "rules.errNoCondition"));
      return;
    }
    idRef.current += 1;
    const rule: UserRule = {
      id: `u${Date.now().toString(36)}${idRef.current.toString(36)}`,
      effect: newEffect,
    };
    for (const [k, v] of Object.entries(candidate)) {
      if (v) (rule as unknown as Record<string, string>)[k] = v;
    }
    // Same checks Save would run (wildcard trap, bad regex, unknown
    // provider/capability…), but immediately — nothing reaches the draft
    // that Save would later reject.
    const { issues } = validateUserRules([rule]);
    if (issues.length > 0) {
      setAddRuleError(issues.map((i) => i.messages.join("; ")).join(" | "));
      return;
    }
    setDraft((d) => (d ? { ...d, rules: [...d.rules, rule] } : d));
    setNewCond({ provider: "", capability: "", commandPattern: "", pathPattern: "", hostPattern: "", workspace: "" });
    setAddRuleError(null);
    setMessage(null);
  };

  const updateNewCond = (k: string, v: string) => {
    setNewCond((prev) => ({ ...prev, [k]: v }));
    setAddRuleError(null);
  };
  const updateNewEffect = (v: string) => {
    setNewEffect(v === "deny" ? "deny" : v === "ask" ? "ask" : "allow");
    setAddRuleError(null);
  };

  const deleteRule = (id: string) => {
    setDraft((d) => (d ? { ...d, rules: d.rules.filter((r) => r.id !== id) } : d));
  };

  const onSave = () => {
    if (settings.status !== "ready" || busy) return;
    setBusy(true);
    setMessage(null);
    (async () => {
      let next: PluginSettings;
      try {
        next = applySettingsDraft(settings.values as PluginSettings, draft.text, draft.toggles, draft.rules);
      } catch (e) {
        setMessage({ ok: false, text: `${t(lang, "settings.invalid")}${e instanceof Error ? e.message : String(e)}` });
        return;
      }
      const okSaved = await settings.save(next, settings.revision);
      if (!okSaved) {
        setMessage({ ok: false, text: `${t(lang, "settings.saveConflict")}${settings.saveError ?? "unknown"}${t(lang, "settings.saveConflictHint")}` });
        return;
      }
      try {
        const res = await callUpdate({ settings: next as unknown as Record<string, unknown> });
        if (res.ok) {
          setMessage({ ok: true, text: `${t(lang, "settings.saved")}${res.rulesVersion})` });
          setSaved(seed(next));
          void live.refetch();
        } else {
          setMessage({ ok: false, text: `${t(lang, "settings.savedHostOnly")}${res.error}` });
        }
      } catch (e) {
        setMessage({ ok: false, text: `${t(lang, "settings.applyFailed")}${e instanceof Error ? e.message : String(e)}` });
      }
    })().finally(() => setBusy(false));
  };

  const advisor = friendlyAdvisor({ raw: live.data?.laya, display: (live.data as { advisor?: string } | undefined)?.advisor });
  const engineOn = live.data?.enabled ?? null;
  const langVal = draft.text.language === "zh" ? "zh" : "en";

  const body = (
    <>
      <View style={s.banner}>
        <Text style={s.bannerTitle}>{t(lang, "settings.title")}</Text>
        <Text style={s.bannerSub}>
          {engineOn === null
            ? t(lang, "settings.liveLoading")
            : `${t(lang, "settings.live")}${engineOn ? t(lang, "settings.liveOn") : t(lang, "settings.liveOff")}${t(lang, "settings.advisor")}${advisor}`}
        </Text>
      </View>

      <View style={s.section}>
        <Text style={s.sectionTitle}>{t(lang, "sec.general")}</Text>
        <View style={s.card}>
          {boolField("enabled", t(lang, "f.enabled"), t(lang, "f.enabledDesc"))}
          <View style={s.fieldGap}>
            <Text style={s.label}>{t(lang, "settings.langLabel")}</Text>
            <Text style={s.desc}>{t(lang, "settings.langDesc")}</Text>
            {seg(langVal,
              [{ v: "zh", label: "中文" }, { v: "en", label: "English" }],
              (v) => setText("language")(v), "pick-lang")}
          </View>
          <View style={s.fieldGap}>
            <Text style={s.label}>{t(lang, "f.policy")}</Text>
            <Text style={s.desc}>{t(lang, "f.policyDesc")}</Text>
            {seg(draft.text.defaultPolicy === "deny" ? "deny" : "ask",
              [{ v: "ask", label: t(lang, "f.policyAsk") }, { v: "deny", label: t(lang, "f.policyDeny") }],
              (v) => setText("defaultPolicy")(v), "pick-policy")}
          </View>
          <View style={s.fieldGap}>
            {boolField("learningEnabled", t(lang, "f.learning"), t(lang, "f.learningDesc"))}
          </View>
        </View>
      </View>

      <View style={s.section}>
        <Text style={s.sectionTitle}>{t(lang, "sec.rules")}</Text>
        <View style={s.card}>
          <Text style={s.desc}>{t(lang, "rules.desc")}</Text>
          <Text style={s.desc}>{t(lang, "rules.hard")}</Text>
          {draft.rules.length === 0 ? (
            <Text style={[s.desc, { marginTop: 8 }]}>{t(lang, "rules.empty")}</Text>
          ) : (
            <View style={s.rulesGrid}>
            {draft.rules.map((r) => (
              <View key={r.id} style={[s.ruleCell, { width: ruleCellWidth }]}>
              <View style={s.ruleCard}>
                <View style={s.ruleHead}>
                  <View style={r.effect === "allow" ? s.badgeAllow : r.effect === "ask" ? s.badgeAsk : s.badgeDeny}>
                    <Text style={[s.badgeText, { color: r.effect === "allow" ? c.statusSuccess : r.effect === "ask" ? c.statusWarning : c.statusDanger }]}>
                      {r.effect === "allow" ? t(lang, "rules.allow") : r.effect === "ask" ? t(lang, "rules.ask") : t(lang, "rules.deny")}
                    </Text>
                  </View>
                  <Pressable
                    accessibilityRole="button" accessibilityLabel={`delete-rule-${r.id}`}
                    style={s.deleteBtn} onPress={() => deleteRule(r.id)}
                  >
                    <Text style={s.deleteText}>{t(lang, "rules.delete")}</Text>
                  </Pressable>
                </View>
                <Text style={s.ruleSummary}>{summarizeRule(r)}</Text>
              </View>
              </View>
            ))}
            </View>
          )}
          <View style={s.fieldGap}>
            <Text style={s.label}>{t(lang, "rules.add")}</Text>
            <Text style={s.desc}>{t(lang, "rules.effect")}</Text>
            {seg(newEffect,
              [{ v: "allow", label: t(lang, "rules.allow") }, { v: "ask", label: t(lang, "rules.ask") }, { v: "deny", label: t(lang, "rules.deny") }],
              updateNewEffect, "pick-rule-effect")}
          </View>
          {(
            [
              ["provider", "rules.provider"],
              ["capability", "rules.capability"],
              ["commandPattern", "rules.command"],
              ["pathPattern", "rules.path"],
              ["hostPattern", "rules.host"],
              ["workspace", "rules.workspace"],
            ] as Array<[string, "rules.provider" | "rules.capability" | "rules.command" | "rules.path" | "rules.host" | "rules.workspace"]>
          ).map(([k, labelKey]) => (
            <View key={k} style={s.fieldGap}>
              <Text style={s.label}>{t(lang, labelKey)}</Text>
              <TextInput
                style={s.input}
                value={newCond[k] ?? ""}
                onChangeText={(v) => updateNewCond(k, v)}
                autoCapitalize="none"
                autoCorrect={false}
              />
            </View>
          ))}
          <Pressable
            accessibilityRole="button" accessibilityLabel="add-rule"
            style={s.addBtn} onPress={addRule}
          >
            <Text style={s.addText}>{t(lang, "rules.add")}</Text>
          </Pressable>
          {addRuleError ? (
            <Text accessibilityLabel="add-rule-error" style={s.msgErr}>{addRuleError}</Text>
          ) : null}
        </View>
      </View>

      <View style={s.section}>
        <Text style={s.sectionTitle}>{t(lang, "sec.jev")}</Text>
        <View style={s.card}>
          {boolField("jevEnabled", t(lang, "f.jevEnabled"), t(lang, "f.jevEnabledDesc"))}
          {textField("jevApiKey", t(lang, "f.jevKey"), t(lang, "f.jevKeyDesc"), true, "sk-or-v1-…")}
          <Pressable style={s.linkBtn} onPress={() => setShowSecrets((v) => !v)}>
            <Text style={s.linkText}>{showSecrets ? t(lang, "settings.hideSecrets") : t(lang, "settings.showSecrets")}</Text>
          </Pressable>
          {textField("jevModel", t(lang, "f.jevModel"), t(lang, "f.jevModelDesc"), false, "jev-1.13-free")}
          {textField("jevEndpoint", t(lang, "f.jevEndpoint"), t(lang, "f.jevEndpointDesc"), false,
            "https://opencode.ai/zen/v1/systemone")}
          {textField("jevTimeoutMs", t(lang, "f.jevTimeout"), t(lang, "f.jevTimeoutDesc"), false, "15000")}
          {textField("jevMinConfidence", t(lang, "f.jevConf"), t(lang, "f.jevConfDesc"), false, "0.6")}
        </View>
      </View>

      <View style={s.section}>
        <Text style={s.sectionTitle}>{t(lang, "sec.laya")}</Text>
        <View style={s.card}>
          {boolField("layaEnabled", t(lang, "f.layaEnabled"), t(lang, "f.layaEnabledDesc"))}
          {textField("layaEndpoint", t(lang, "f.layaEndpoint"), t(lang, "f.layaEndpointDesc"), false, "http://127.0.0.1:17890/decide")}
          {textField("layaToken", t(lang, "f.layaToken"), t(lang, "f.layaTokenDesc"), true)}
          {textField("layaTimeoutMs", t(lang, "f.layaTimeout"), t(lang, "f.layaTimeoutDesc"), false, "15000")}
          {textField("layaMinConfidence", t(lang, "f.layaConf"), t(lang, "f.layaConfDesc"), false, "0.6")}
        </View>
      </View>

      <View style={s.section}>
        <Text style={s.sectionTitle}>{t(lang, "sec.perf")}</Text>
        <View style={s.card}>
          {textField("cacheTtlSec", t(lang, "f.cacheTtl"), t(lang, "f.cacheTtlDesc"), false, "60")}
          {textField("layaMaxConcurrency", t(lang, "f.concurrency"), t(lang, "f.concurrencyDesc"), false, "4")}
        </View>
      </View>

      <Pressable
        accessibilityRole="button" accessibilityLabel="save-settings"
        style={[s.saveBtn, busy ? s.saveBtnDisabled : null]}
        onPress={onSave}
      >
        <Text style={s.saveText}>{busy ? t(lang, "settings.saving") : t(lang, "settings.save")}</Text>
      </Pressable>
      {dirty ? <Text style={s.dirty}>{t(lang, "settings.dirty")}</Text> : null}
      {message ? <Text style={message.ok ? s.msgOk : s.msgErr}>{message.text}</Text> : null}
    </>
  );
  if (embedded) {
    return <View style={s.wrap}>{body}</View>;
  }
  return (
    <ScrollView
      style={{ flex: 1 }}
      contentContainerStyle={s.wrap}
      showsVerticalScrollIndicator
    >
      {body}
    </ScrollView>
  );
}
