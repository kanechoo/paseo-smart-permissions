import type { PluginClientContext } from "@getpaseo/plugin/client";
import { MonitorSurface } from "./monitor.js";
import { SettingsPanel } from "./settings.js";

export default function contribute(client: PluginClientContext) {
  client.addSurface("smart-permissions", MonitorSurface);
  client.addSettingsScreen({
    id: "smart-permissions-settings",
    title: "Settings",
    icon: "Settings",
    Component: SettingsPanel,
  });
  client.addSidebarItem({
    id: "smart-permissions",
    title: "Smart Permissions",
    icon: "ShieldCheck",
    surface: "smart-permissions",
  });
  return () => {};
}
