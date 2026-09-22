/** Friendly advisor labels for the dashboard.
 *  Server sends `advisor` (display name) when available; older servers only
 *  send the raw `laya` client name, so map that as a fallback. Never show a
 *  bare "laya.*" id to users when Jev actually decided. */
export function advisorDisplayFallback(raw: string | undefined | null): string {
  const n = (raw ?? "").toLowerCase();
  if (n.startsWith("jev")) return "Jev";
  if (n.startsWith("laya.http")) return "Laya";
  if (n.startsWith("advisory")) return "Jev+Laya";
  return "off";
}

export function friendlyAdvisor(args: { raw?: string | null; display?: string | null }): string {
  const display = (args.display ?? "").trim();
  if (display && display !== "Advisor") return display;
  const raw = (args.raw ?? "").trim();
  if (!raw || raw === "…" ) return "…";
  const n = raw.toLowerCase();
  if (n.startsWith("jev")) return "Jev";
  if (n.startsWith("laya.http")) return "Laya";
  if (n.startsWith("advisory")) return display || "Jev+Laya";
  if (n.startsWith("laya.disabled") || n.startsWith("disabled")) return "off";
  return display || raw;
}

/** Stats line: `advisor=Jev (jev.openrouter)` keeps attribution clear but raw debuggable. */
export function statsAdvisorLabel(raw: string | undefined | null, display?: string | null): string {
  const friendly = friendlyAdvisor({ raw, display });
  if ((friendly === "Jev" || friendly === "Laya" || friendly === "Jev+Laya") && raw && raw !== friendly) {
    return `${friendly} (${raw})`;
  }
  return friendly;
}
