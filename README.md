# Paseo Smart Permissions

**English** | [中文](README.zh-CN.md)

Unified, default-safe permission decisions for AI coding agents — one policy engine for
**Pi / OpenCode / Codex / Claude**, running as a [Paseo](https://opencode.ai) plugin
(Paseo ≥ 0.8.0, Plugin SDK 0.8.0).

Every permission request is normalized into a single intermediate representation, then
decided deterministically as `ALLOW / ASK / DENY`:

- `ALLOW` / `DENY` — answered automatically via `respondToPermission`, no popup lingers.
- `ASK` — left pending on purpose, so the request stays in Paseo's native approval UI
  for a human to judge.

## Why this exists

Each agent backend reports permissions in its own dialect, with its own defaults. That
leaves you with N approval popups to configure and no single place to answer "why was
this allowed?". This plugin collapses all of that into one pipeline: normalize once,
apply your rules, consult an advisory model only when nothing deterministic fires, and
record every auto-decision in an audit log you can grep.

## Features

- **One engine, four providers** — Pi, OpenCode, Codex and Claude requests share the
  same risk model, rule language and audit trail.
- **Layered decision pipeline** — hard-deny guards → user rules (`deny > ask > allow`)
  → learned patterns → advisory models (Jev / Laya) → safe default. Advisors are
  signals, never the security boundary.
- **Jev advisory out of the box** — defaults to the OpenCode Zen free tier
  (`jev-1.13-free`), so a fresh install only needs an API key pasted in. OpenRouter
  and self-hosted Decisions-API endpoints work too.
- **Optional local advisor (Laya)** — a typed-decision HTTP service on localhost for
  fully local verdicts; runs alone or conservatively merged with Jev (strictest wins).
- **Learning from humans** — repeated LOW-risk human approvals crystallize into
  expiring learned rules; nothing HIGH-risk is ever learned.
- **Fail-closed everywhere** — advisor down, timed out, or off-schema → `ASK` on
  LOW/MEDIUM, `DENY` on HIGH/CRITICAL. The agent turn is never hung and never
  silently released.
- **Secret-safe by construction** — commands, payloads, audit entries and cache keys
  are sanitized/redacted before they touch the network, the log, or the cache.
- **Live dashboard** — stats, recent decisions (with per-decision latency and the
  advisor behind it), and the full settings editor with inline rule validation.

## How it works

```
agent request
    │  normalize (provider, capability, command, paths, hosts, risk)
    ▼
┌─────────────┐
│  HARD DENY  │  secrets · workspace escape · destructive commands · curl|sh …
└──────┬──────┘
       ▼  no hit
┌─────────────┐
│ USER RULES  │  deny  →  DENY
│             │  ask   →  ASK (human review, advisors skipped)
│             │  allow →  ALLOW (workspace-escape guard still applies)
└──────┬──────┘
       ▼  no hit
┌─────────────┐
│   LEARNED   │  LOW-risk only, needs repeat human approvals, expires
└──────┬──────┘
       ▼  no hit
┌─────────────┐
│  ADVISORS   │  Jev and/or Laya · low confidence degrades to ASK
└──────┬──────┘
       ▼  unavailable
┌─────────────┐
│   DEFAULT   │  ask (native UI) or deny, your choice
└─────────────┘
```

Rule matching supports exact, substring, `/regex/`, and glob (`*`, `**`) conditions on
provider, capability, command, path, host, and workspace prefix. Workspace matching is
boundary-aware (`/w/project` never matches the sibling `/w/project2`).

## Quick start

```bash
paseo plugin install /path/to/paseo-smart-permissions
```

1. Open the plugin dashboard (**Smart Permissions** in the sidebar).
2. Paste an API key into **Jev → API key** — any OpenCode Zen key works, including
   with the free `jev-1.13-free` model. No other configuration is required.
3. (Recommended) Start with the engine observing: leave high-stakes commands without
   allow rules so they come to you as `ASK`, approve the safe ones, and let learning
   plus your own rules take over from there.

Going fully local? Enable **Laya** instead and point it at your typed-decision
service (`POST` JSON `{ schema, request }` + `Bearer` token → `{ decision,
confidence, reason, risk }`).

## Configuration

All settings live in the dashboard editor (`smart-permissions-settings`, host scope)
with inline validation — a rule that could never match, or one that would match
everything, is rejected at Add time with a fix hint, not at Save time.

| Area | Key settings |
|---|---|
| General | `enabled`, `defaultPolicy` (`ask` keeps native UI, `deny` fails closed), `language` |
| User rules | `userRules[]` — `{ effect: allow \| ask \| deny, provider?, capability?, commandPattern?, pathPattern?, hostPattern?, workspace? }` |
| Jev | `jevEnabled`, `jevApiKey`, `jevModel` (`jev-1.13-free`), `jevEndpoint`, `jevTimeoutMs`, `jevMinConfidence` |
| Laya | `layaEnabled`, `layaEndpoint`, `layaToken`, `layaTimeoutMs`, `layaMinConfidence` |
| Performance | `cacheTtlSec` (ALLOW-verdict cache, seconds, `0` disables), `layaMaxConcurrency`, `learningEnabled` |

Rules are validated semantically on every save path (dashboard and RPC): unknown
providers/capabilities with did-you-mean hints, `*` in command patterns (matched
literally — use a substring or `/regex/`), invalid regexes, non-absolute workspaces,
bare-hostname violations, duplicate ids, and condition-free allow/ask rules.

## Dashboard

- **Stats** — totals by decision, cache hit/miss, learned-rule count, active advisor.
- **Recent decisions** — the last 30 auto-decisions, each with final decision, risk,
  source, the responsible advisor (`via Jev` / `via Laya`), decision latency in ms,
  and the human-readable reason.
- **Settings** — the same editor as the settings screen, embedded below the activity
  so it stays reachable no matter how long the log grows.

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest — 166 tests across 17 files
```

Project layout:

```
client/   dashboard surface, settings editor, i18n (en + zh)
server/   IR build, rule engine, advisors (Jev/Laya/composite), audit, cache
shared/   settings schema + rule validation, RPC contracts
tests/    engine, rules, providers, advisors, security, e2e
```

## Security model

- Advisors (Jev/Laya) are **advisory only**: they cannot override hard-deny or user
  rules, and every failure mode degrades to human review or denial.
- `ALLOW` verdicts apply to LOW/MEDIUM risk with sufficient confidence; HIGH/CRITICAL
  can only be released by an explicit user rule — and never against a hard-deny.
- Learned rules cover LOW risk exclusively, require repeated human approvals, and expire.
- Secrets never leave the machine in the clear: redaction runs before advisor calls,
  audit writes, and cache keys.

## FAQ

**A popup flashes and disappears on auto-allowed requests — is that a bug?**
No. Paseo 0.8.0 shows the native approval UI the moment a request arrives; the plugin
can only resolve it afterwards via `respondToPermission`, so the visible flash equals
decision latency (shown per row in ms). Rule/learned/cache hits resolve in
milliseconds and effectively never flash; advisor roundtrips take longer. The SDK
offers no synchronous intercept — when it does, this plugin will adopt it.

**Do I need OpenRouter?**
No. The default backend is the OpenCode Zen free tier. OpenRouter (`typesafe/jev-1.13`
at `https://openrouter.ai/api/alpha/decisions`) remains a supported alternative, as is
any Decisions-API-compatible server.

**Why was my rule rejected at Add time?**
The editor runs the same semantic validation as Save: most commonly a `*` in a
command pattern (literal there — use a substring or `/regex/`), an unknown
provider/capability typo, or an allow/ask rule with zero match conditions.

**Which advisor decided this?**
Each recent-decision row names it (`via Jev`, `via Laya`, `via Jev+Laya`) and the
reason string is always attributed to the advisor that actually ran — never a stale
provider name.
