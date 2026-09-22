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
  it("detect/resolve: node (no navigator) -> en; explicit respected", async () => {
    const { detectLang, resolveLang } = await import("../client/i18n.js");
    expect(detectLang()).toBe("en");
    expect(resolveLang("zh")).toBe("zh");
    expect(resolveLang("en")).toBe("en");
    expect(resolveLang("system")).toBe("en");
    expect(resolveLang(undefined)).toBe("en");
  });
  it("t() returns strings for both langs", async () => {
    const { t } = await import("../client/i18n.js");
    expect(t("en", "settings.save")).toBe("Save settings");
    expect(t("zh", "settings.save")).toBe("保存设置");
  });
});

describe("language setting plumbing", () => {
  it("schema defaults to system", () => {
    expect(defaultSettings().language).toBe("system");
  });
  it("draft applies valid language, ignores garbage", () => {
    expect(applySettingsDraft(defaultSettings(), { language: "zh" }, {}).language).toBe("zh");
    expect(applySettingsDraft(defaultSettings(), { language: "fr" }, {}).language).toBe("system");
  });
});
