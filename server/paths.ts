/** Workspace boundary + symlink-escape defense (best-effort, fail-closed). */
import * as fs from "node:fs";
import * as path from "node:path";
import { isSecretFileName } from "./redact.js";

const SENSITIVE_DIRS_POSIX = [
  "/etc", "/var", "/sys", "/proc", "/root",
];

const SENSITIVE_HOME_DIRS = [
  ".ssh", ".aws", ".gnupg", ".config/gcloud", ".azure", ".kube",
];

function normalizeSeparators(p: string): string {
  return p.replace(/\\/g, "/");
}

/** Lexical containment check (no fs access). Case-insensitive on darwin/win32. */
export function lexicallyContains(workspaceCwd: string, target: string): boolean {
  const ws = path.resolve(workspaceCwd);
  const abs = path.resolve(workspaceCwd, target);
  const rel = path.relative(ws, abs);
  if (rel === "" || rel === ".") return true;
  if (rel === ".." || rel.startsWith(`..${path.sep}`)) return false;
  if (path.isAbsolute(rel)) return false; // different drive (win32)
  if (process.platform === "darwin" || process.platform === "win32") {
    // Cheap case-insensitive guard: compare lowercased char-by-char.
    const wsLower = ws.toLowerCase();
    const absLower = abs.toLowerCase();
    if (absLower !== wsLower && !absLower.startsWith(wsLower + path.sep.toLowerCase())) return false;
  }
  void normalizeSeparators;
  return true;
}

export interface ResolvedPath {
  /** Absolute lexical path. */
  absolute: string;
  /** Absolute real path if resolvable, else null. */
  real: string | null;
  insideWorkspace: boolean;
  insideWorkspaceReal: boolean | null; // null when unresolvable
  isSensitive: boolean;
  sensitiveReason?: string;
  isSecretFile: boolean;
}

function deepestExistingDir(abs: string): string {
  let cur = abs;
  for (;;) {
    try {
      const st = fs.lstatSync(cur);
      void st;
      return cur;
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return cur;
      cur = parent;
    }
  }
}

export function isSensitiveAbsolute(abs: string): string | null {
  const lower = abs.toLowerCase();
  for (const d of SENSITIVE_DIRS_POSIX) {
    if (lower === d || lower.startsWith(d + "/")) return `system dir ${d}`;
  }
  const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
  if (home) {
    const h = path.resolve(home).toLowerCase();
    for (const d of SENSITIVE_HOME_DIRS) {
      const full = `${h}/${d}`;
      if (lower === full || lower.startsWith(full + "/")) return `home credential dir ~/${d}`;
    }
    // Any dotfile directly under $HOME is suspicious for writes.
    const relHome = path.relative(h, lower);
    if (relHome !== "" && !relHome.startsWith("..") && /^[.][^/]*$/.test(relHome.split("/")[0] ?? "")) {
      return `dotfile under $HOME`;
    }
  }
  return null;
}

function tryReal(p: string): string | null {
  try { return fs.realpathSync(p); } catch { return null; }
}

function contained(base: string, target: string): boolean {
  const rel = path.relative(base, target);
  return !(rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel));
}

/** Resolve a request path against the workspace with symlink defense. */
export function resolveRequestPath(workspaceCwd: string, requestPath: string): ResolvedPath {
  const ws = path.resolve(workspaceCwd);
  // Normalize the workspace itself (macOS: /var -> /private/var, /etc -> /private/etc).
  const wsReal = tryReal(ws) ?? ws;
  const absolute = path.resolve(workspaceCwd, requestPath);
  const insideWorkspace = lexicallyContains(workspaceCwd, requestPath);

  let real: string | null = null;
  let insideWorkspaceReal: boolean | null = null;
  try {
    // If the exact path exists (file or symlink), resolve it directly.
    real = fs.realpathSync(absolute);
  } catch {
    try {
      // Otherwise resolve the deepest existing parent and re-append the rest.
      const base = deepestExistingDir(absolute);
      const baseReal = fs.realpathSync(base);
      real = path.join(baseReal, path.relative(base, absolute));
    } catch {
      real = null;
    }
  }
  if (real !== null) {
    insideWorkspaceReal = contained(wsReal, real);
  }

  // Check BOTH lexical and resolved paths: a symlinked /etc must not slip through.
  const sensitiveAbs = isSensitiveAbsolute(absolute) ?? (real !== null ? isSensitiveAbsolute(real) : null);
  return {
    absolute,
    real,
    insideWorkspace,
    insideWorkspaceReal,
    isSensitive: sensitiveAbs !== null,
    sensitiveReason: sensitiveAbs ?? undefined,
    isSecretFile: isSecretFileName(absolute),
  };
}

/** Classify a batch of paths; returns worst-case flags for rule evaluation. */
export function classifyPaths(workspaceCwd: string, paths: string[]): {
  escape: boolean;
  symlinkEscape: boolean;
  unresolvable: boolean;
  sensitive: boolean;
  secretFile: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  let escape = false, symlinkEscape = false, unresolvable = false;
  let sensitive = false, secretFile = false;
  for (const p of paths) {
    const r = resolveRequestPath(workspaceCwd, p);
    if (!r.insideWorkspace) { escape = true; reasons.push(`path escapes workspace: ${p}`); }
    // Only a lexical-inside path resolving outside counts as symlink escape;
    // lexical-outside paths are plain escapes (handled above).
    if (r.insideWorkspace && r.insideWorkspaceReal === false) { symlinkEscape = true; reasons.push(`symlink escapes workspace: ${p}`); }
    if (r.insideWorkspaceReal === null && r.insideWorkspace) {
      unresolvable = true; reasons.push(`symlink-unresolvable, treat as outside: ${p}`);
    }
    if (r.isSensitive) { sensitive = true; reasons.push(`sensitive path (${r.sensitiveReason}): ${p}`); }
    if (r.isSecretFile) { secretFile = true; reasons.push(`secret file: ${p}`); }
  }
  return { escape, symlinkEscape, unresolvable, sensitive, secretFile, reasons };
}
