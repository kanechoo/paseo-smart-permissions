/** Shell command analysis: quote-aware split, chain detection, danger classification. */

export interface CommandPart {
  text: string;          // sub-command text
  argv: string[];        // tokenized argv (quote-aware, best-effort)
  executable: string;    // argv[0] basename, lowercased
}

export interface CommandAnalysis {
  parts: CommandPart[];
  chained: boolean;      // && || ; | pipeline present
  hasPipeToShell: boolean;
  hasCommandSubstitution: boolean;
  hasRedirect: boolean;
  danger: "NONE" | "HIGH" | "CRITICAL";
  dangerReasons: string[];
}

const CHAIN_OPS = ["&&", "||", ";", "|", "&"];

const CRITICAL_PATTERNS: Array<{ re: RegExp; reason: string }> = [
  { re: /\brm\s+(-[^|;&]*\s+)?(\/|~|\$HOME|\*)/, reason: "delete of root/home/wildcard" },
  { re: /\b(mkfs|dd\b[^|]*\bof=|diskpart|format\s+[a-z]:)/i, reason: "disk destructive tool" },
  { re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/, reason: "fork bomb" },
  { re: /\bchmod\s+(-R\s+)?777\b/i, reason: "chmod 777" },
  { re: /\bchown\s+-R\b/i, reason: "recursive chown" },
  { re: /\bsudo\b/i, reason: "privilege escalation (sudo)" },
  { re: /\bsu\b\s+-/i, reason: "privilege escalation (su)" },
  { re: /eval\s+["']?\$\(/i, reason: "eval of command substitution" },
];

const HIGH_PATTERNS: Array<{ re: RegExp; reason: string }> = [
  { re: /\brm\s+[^|;&]*-[a-z]*r[a-z]*f\b/i, reason: "recursive force delete" },
  { re: /\bgit\s+push\s+.*--force\b/i, reason: "git push --force" },
  { re: /\bgit\s+reset\s+--hard\b/i, reason: "git reset --hard" },
  { re: /\bgit\s+clean\s+-[a-z]*f/i, reason: "git clean -f" },
  { re: /\bgit\s+checkout\s+[^-]/i, reason: "git checkout (branch switch)" },
  { re: /\b(chmod\s+[+]x|chmod\s+755|chmod\s+700)\b/i, reason: "chmod making executable" },
  { re: /\bnpm\s+publish\b/i, reason: "npm publish" },
  { re: /\bpip\s+install\b/i, reason: "pip install (arbitrary code)" },
  { re: /\bcurl\b[^|;&]*\|\s*(sh|bash|zsh)\b/i, reason: "curl piped to shell" },
  { re: /\bwget\b[^|;&]*\|\s*(sh|bash|zsh)\b/i, reason: "wget piped to shell" },
  { re: /\|\s*(sh|bash|zsh)(\s|$)/i, reason: "pipe into shell" },
  { re: /\bssh\b/i, reason: "ssh remote execution" },
  { re: /\b(nc|netcat|ncat)\b/i, reason: "netcat" },
  { re: /\bshutdown\b|\breboot\b/i, reason: "shutdown/reboot" },
  { re: /\bkill\s+-9\s+-1\b/, reason: "kill all processes" },
];

/** Known-safe read-only / project-local commands (exact executable + subcommand). */
const LOW_ALLOWLIST: RegExp[] = [
  /^(git\s+(status|diff|log|show|branch($|\s)|stash\s+list|remote\s+-v))\b/i,
  /^(npm\s+(test|run\s+(build|lint|typecheck)|ls))\b/i,
  /^(npx\s+tsc\b)/i,
  /^(go\s+(test|build|vet)(\s|$))/i,
  /^(cargo\s+(test|build|check)(\s|$))/i,
  /^(ls|pwd|echo|cat|head|tail|wc|which|node\s+--version|python3?\s+--version)(\s|$)/i,
];

/** Split top-level on chain operators, respecting single/double quotes + backticks. */
export function splitChain(command: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let depth = 0; // $() nesting
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") { quote = ch; cur += ch; continue; }
    if (ch === "$" && command[i + 1] === "(") { depth++; cur += ch; continue; }
    if (ch === ")" && depth > 0) { depth--; cur += ch; continue; }
    if (depth === 0) {
      const two = command.slice(i, i + 2);
      if (two === "&&" || two === "||") {
        parts.push(cur.trim()); cur = ""; i++; continue;
      }
      if (ch === ";" || ch === "|" || ch === "&") {
        parts.push(cur.trim()); cur = ""; continue;
      }
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts.filter(Boolean);
}

/** Quote-aware argv tokenization (handles VAR=val prefixes). */
export function tokenize(part: string): string[] {
  const argv: string[] = [];
  let cur = "";
  let quote: string | null = null;
  const push = () => { if (cur !== "") { argv.push(cur); cur = ""; } };
  for (let i = 0; i < part.length; i++) {
    const ch = part[i]!;
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (/\s/.test(ch)) { push(); continue; }
    cur += ch;
  }
  push();
  // Strip leading VAR=... env assignments for executable detection.
  while (argv.length > 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0]!)) argv.shift();
  return argv;
}

export function analyzeCommand(command: string): CommandAnalysis {
  const rawParts = splitChain(command);
  const parts: CommandPart[] = rawParts.map((text) => {
    const argv = tokenize(text).filter((t) => t !== "sudo"); // sudo handled as danger, not exe
    const exe = (argv[0] ?? "").split(/[\\/]/).pop()?.toLowerCase() ?? "";
    return { text, argv, executable: exe };
  });
  const chained = rawParts.length > 1 || /\|\s*\S/.test(command);
  const hasPipeToShell = /(curl|wget)[^|]*\|\s*(sh|bash|zsh)/i.test(command) || /\|\s*(sh|bash|zsh)(\s|$)/i.test(command);
  const hasCommandSubstitution = /\$\(/.test(command) || /`[^`]*`/.test(command);
  const hasRedirect = /[0-9]?[<>]{1,2}\s*\S/.test(command);

  const dangerReasons: string[] = [];
  let danger: CommandAnalysis["danger"] = "NONE";
  for (const { re, reason } of CRITICAL_PATTERNS) {
    if (re.test(command)) { danger = "CRITICAL"; dangerReasons.push(reason); }
  }
  if (danger === "NONE") {
    for (const { re, reason } of HIGH_PATTERNS) {
      if (re.test(command)) { danger = "HIGH"; dangerReasons.push(reason); }
    }
  }
  if (hasPipeToShell && danger === "NONE") { danger = "HIGH"; dangerReasons.push("pipe into shell"); }
  return { parts, chained, hasPipeToShell, hasCommandSubstitution, hasRedirect, danger, dangerReasons };
}

export function isLowAllowlisted(command: string): boolean {
  return LOW_ALLOWLIST.some((re) => re.test(command.trim()));
}

/** Credential/secret hints: output commands (cat/head/tail/…) must not count
 *  as known-safe when they touch these — shell output would otherwise bypass
 *  the secret-file overlay that protects file.read. */
const SHELL_SECRET_HINT = /(\.env\b|\.ssh\b|\.aws\b|\.gnupg\b|id_rsa|\.pem\b|\.npmrc\b|credential|secret|\/etc\/|passwd)/i;

/** Known-safe shell baseline: allowlisted executable, single command (no chains),
 *  no substitution/redirect, no secret hints. Hard rules and user rules still
 *  run before any auto-allow, so this only lowers the *baseline* for the
 *  advisor — it can never release a destructive/escaping command by itself. */
export function isKnownSafeCommand(command: string): boolean {
  const a = analyzeCommand(command);
  if (a.danger !== "NONE" || a.chained || a.hasCommandSubstitution || a.hasRedirect) return false;
  if (SHELL_SECRET_HINT.test(command)) return false;
  return isLowAllowlisted(command);
}
