import { describe, expect, it } from "vitest";
import { defaultSettings } from "../shared/config.js";
import { applySettingsDraft } from "../shared/settings-def.js";

// i18n.ts lives in client/ (RN); import the pure parts only via dynamic import
// to keep the node test env honest (no navigator -> detectLang falls back to en).
describe("i18n", () => {
  it("zh/en tables share the exact key set", async () => {
    const fs = await import("node:fs");
    const src = fs.readFileSync(new URL("../client/i18n.ts", import.meta.url), "utf8");
    const enKeys = [...src.matchAll(/^  "([^"]+)": /gm)].map((m) => m[1]);
    // en block ends where `} as const;` closes it; zh block is Record<StringKey,...>
    expect(enKeys.length).toBeGreaterThan(30);
    const zhBlock = src.slice(src.indexOf("const zh"));
    for (const k of enKeys) expect(zhBlock).toContain(`"${k}"`);
  });
  it("resolve: zh respected, everything else (legacy system/undefined/garbage) -> en", async () => {
    const { resolveLang } = await import("../client/i18n.js");
    expect(resolveLang("zh")).toBe("zh");
    expect(resolveLang("en")).toBe("en");
    expect(resolveLang("system")).toBe("en");
    expect(resolveLang(undefined)).toBe("en");
    expect(resolveLang("fr")).toBe("en");
  });
  it("t() returns strings for both langs", async () => {
    const { t } = await import("../client/i18n.js");
    expect(t("en", "settings.save")).toBe("Save settings");
    expect(t("zh", "settings.save")).toBe("保存设置");
  });
});

describe("language setting plumbing", () => {
  it("schema defaults to en", () => {
    expect(defaultSettings().language).toBe("en");
  });
  it("draft applies zh/en, ignores garbage", () => {
    expect(applySettingsDraft(defaultSettings(), { language: "zh" }, {}).language).toBe("zh");
    expect(applySettingsDraft(defaultSettings(), { language: "en" }, {}).language).toBe("en");
    expect(applySettingsDraft(defaultSettings(), { language: "fr" }, {}).language).toBe("en");
    expect(applySettingsDraft(defaultSettings(), { language: "system" }, {}).language).toBe("en");
  });
  it("legacy stored values never brick a save (system/garbage -> en)", async () => {
    const { migrateSettings } = await import("../shared/settings-def.js");
    const { parseSettings } = await import("../shared/config.js");
    expect((migrateSettings({ language: "system" }) as { language: string }).language).toBe("en");
    expect(parseSettings({ language: "system" }).language).toBe("en");
    expect(parseSettings({}).language).toBe("en");
  });
});
