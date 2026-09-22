/** Secret detection + redaction. Applied BEFORE anything leaves the engine
 *  (Laya payloads, audit log, cache keys). Fail-closed: on doubt, redact. */

const SECRET_ASSIGNMENT =
  /((?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret|password|passwd|pwd|private[_-]?key|client[_-]?secret|aws[_-]?secret|github[_-]?token|openai[_-]?key|anthropic[_-]?key|bearer)[_a-z0-9-]*)(\s*[:=]\s*)(["']?)([^\s"';,]+)(["']?)/gi;

const TOKEN_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9-_]{8,}\b/g, // OpenAI-style
  /\bghp_[A-Za-z0-9]{8,}\b/g,
  /\bgho_[A-Za-z0-9]{8,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{8,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{8,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\beyJ[A-Za-z0-9-_]{8,}\.[A-Za-z0-9-_]{8,}\.[A-Za-z0-9-_]{8,}\b/g, // JWT
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4000}?-----END [A-Z ]*PRIVATE KEY-----/g,
];

const URL_CREDENTIAL = /(\bhttps?:\/\/)([^/\s:@]+)(:)([^/\s@]+)(@)/gi;

export const SECRET_FILE_BASENAMES = new Set([
  ".env", ".env.local", ".env.production", ".env.development",
  "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
  "credentials.json", "service-account.json", "gcp-key.json",
  ".npmrc", ".pypirc", "secrets.yaml", "secrets.yml", "secrets.json",
  ".aws-credentials", "kube-config", "kubeconfig",
]);

const SECRET_FILE_SUFFIXES = [".pem", ".key", ".p12", ".pfx", ".kdbx"];

export function isSecretFileName(filePath: string): boolean {
  const base = filePath.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  if (SECRET_FILE_BASENAMES.has(base)) return true;
  if (base.startsWith(".env.")) return true;
  return SECRET_FILE_SUFFIXES.some((s) => base.endsWith(s));
}

export function redactSecrets(input: string): string {
  let out = input.replace(SECRET_ASSIGNMENT, "$1$2$3[REDACTED]$5");
  for (const re of TOKEN_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, "[REDACTED]");
  }
  URL_CREDENTIAL.lastIndex = 0;
  out = out.replace(URL_CREDENTIAL, "$1[REDACTED]:[REDACTED]$5");
  return out;
}

/** Truncate long fields for logs; keeps head + length marker. */
export function truncate(text: string, max = 500): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + `…[truncated ${text.length - max} chars]`;
}

/** Redact for audit/cache/laya: redact secrets then truncate. */
export function sanitize(text: string, max = 1000): string {
  return truncate(redactSecrets(text), max);
}
