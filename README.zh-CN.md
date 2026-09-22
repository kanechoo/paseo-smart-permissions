# Paseo Smart Permissions

[English](README.md) | **中文**

面向 AI 编程助手的统一、默认安全的权限决策插件——**Pi / OpenCode / Codex / Claude**
共用一套政策引擎，运行于 [Paseo](https://opencode.ai) 之上（Paseo ≥ 0.8.0，插件 SDK 0.8.0）。

每个权限请求都会被归一成统一的中间表示，再确定性地裁决为 `ALLOW / ASK / DENY`：

- `ALLOW` / `DENY` —— 经 `respondToPermission` 自动答复，不残留弹窗。
- `ASK` —— 故意不响应，请求留在 Paseo 原生审批 UI 里等人来判。

## 为什么做这个

每个 agent 后端上报权限的方言和默认值各不相同：N 个审批弹窗要分别配置，还没有一个统一的地方回答"这条为什么被放行"。本插件把它们收敛成一条管线：归一一次、应用你的规则、只有确定性规则都不命中时才问顾问模型，每次自动裁决都记进可检索的审计日志。

## 功能

- **一个引擎，四种后端** —— Pi、OpenCode、Codex、Claude 共用同一套风险模型、规则语言和审计轨迹。
- **分层决策管线** —— hard-deny 防线 → 用户规则（`deny > ask > allow`）→ 学习规则 → 顾问模型（Jev / Laya）→ 安全默认值。顾问只是信号，永远不是安全边界。
- **开箱即用的 Jev 顾问** —— 默认走 OpenCode Zen 免费版（`jev-1.13-free`），全新安装只需粘贴一个 API key。OpenRouter 和自建 Decisions-API 端点同样支持。
- **可选本地顾问（Laya）** —— localhost 上的类型化决策 HTTP 服务，负责完全本地的裁决；可单独运行，也可与 Jev 保守合并（取最严）。
- **向人类学习** —— 重复出现的人工低风险放行会沉淀为带过期时间的学习规则；高风险永远不学。
- **处处 fail-closed** —— 顾问缺席、超时、返回非法，一律降级：LOW/MEDIUM 转人工，HIGH/CRITICAL 直接拒绝。agent 流程既不悬挂，也不静默放行。
- **默认脱敏** —— 命令、载荷、审计记录、缓存 key 在触网、落盘之前全部做脱敏/打码。
- **实时面板** —— 统计、最近决策（含每条耗时和背后的顾问）、带内联规则校验的完整设置编辑器。

## 工作原理

```
agent 请求
    │  归一（后端、能力、命令、路径、主机、风险）
    ▼
┌─────────────┐
│  HARD DENY  │  密钥文件 · workspace 越界 · 危险命令 · curl|sh …
└──────┬──────┘
       ▼  未命中
┌─────────────┐
│  用户规则   │  deny  →  拒绝
│             │  ask   →  转人工（跳过学习与顾问）
│             │  allow →  放行（workspace 越界防线依然生效）
└──────┬──────┘
       ▼  未命中
┌─────────────┐
│  学习规则   │  仅 LOW 风险，需多次人工确认，会过期
└──────┬──────┘
       ▼  未命中
┌─────────────┐
│  顾问模型   │  Jev 和/或 Laya · 低置信度降级转人工
└──────┬──────┘
       ▼  不可用
┌─────────────┐
│  默认策略   │  ask（走原生 UI）或 deny，二选一
└─────────────┘
```

规则支持按后端、能力、命令、路径、主机、workspace 前缀做精确、子串、`/正则/`、glob（`*`、`**`）匹配。workspace 匹配是边界感知的（`/w/project` 永远不会命中兄弟目录 `/w/project2`）。

## 快速开始

```bash
paseo plugin install /path/to/paseo-smart-permissions
```

1. 打开插件面板（侧栏 **Smart Permissions**）。
2. 在 **Jev → API key** 粘贴 key——任意 OpenCode Zen key 即可，配合免费的 `jev-1.13-free` 模型，无需其他配置。
3. （推荐）先观察后放行：高风险命令不配 allow 规则，让它们以 `ASK` 来到你面前，安全的点几次放行，之后学习规则和你自己的规则会接管。

想完全本地？启用 **Laya** 并指向你的类型化决策服务（`POST` JSON `{ schema, request }` + `Bearer` token → 返回 `{ decision, confidence, reason, risk }`）。

## 配置

所有设置都在面板编辑器里（`smart-permissions-settings`，host 作用域）并带内联校验：永远匹配不上、或会匹配一切的规则，在点 Add 时就被拦下并给出修复提示，不会等到 Save 才炸。

| 分类 | 主要设置项 |
|---|---|
| 通用 | `enabled`、`defaultPolicy`（`ask` 走原生 UI，`deny` 直接拒绝）、`language` |
| 用户规则 | `userRules[]` —— `{ effect: allow \| ask \| deny, provider?, capability?, commandPattern?, pathPattern?, hostPattern?, workspace? }` |
| Jev | `jevEnabled`、`jevApiKey`、`jevModel`（`jev-1.13-free`）、`jevEndpoint`、`jevTimeoutMs`、`jevMinConfidence` |
| Laya | `layaEnabled`、`layaEndpoint`、`layaToken`、`layaTimeoutMs`、`layaMinConfidence` |
| 性能 | `cacheTtlSec`（ALLOW 裁决缓存，单位秒，`0` 关闭）、`layaMaxConcurrency`、`learningEnabled` |

规则在每条存盘链路（面板和 RPC）都会过语义校验：未知后端/能力（带"你是不是想写"提示）、命令里的 `*`（按字面匹配——请用子串或`/正则/`）、非法正则、非绝对路径 workspace、host 没写成裸域名、重复 id、无条件的 allow/ask 规则。

## 面板

- **统计** —— 按裁决分类的总数、缓存命中/未命中、学习规则数、当前顾问。
- **最近决策** —— 最近 30 条自动裁决，每条含最终决定、风险、来源、负责的顾问（`via Jev` / `via Laya`）、决策耗时（毫秒）和可读的理由。
- **设置** —— 与设置页同一个编辑器，嵌在动态下方，日志再长也永远够得着。

## 开发

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest —— 17 个文件 166 个用例
```

项目结构：

```
client/   面板、设置编辑器、中英 i18n
server/   IR 构建、规则引擎、顾问（Jev/Laya/混合）、审计、缓存
shared/   设置 schema + 规则校验、RPC 契约
tests/    引擎、规则、多后端、顾问、安全、端到端
```

## 安全模型

- 顾问（Jev/Laya）**只是顾问**：压不住 hard-deny 和用户规则，任何故障都降级为人工或拒绝。
- `ALLOW` 只处理 LOW/MEDIUM 风险且需足够置信度；HIGH/CRITICAL 只能由显式用户规则放行——且永远越不过 hard-deny。
- 学习规则只覆盖 LOW 风险，需要多次人工确认，会过期。
- 密钥不明文离机：调顾问、写审计、算缓存 key 之前先脱敏。

## 常见问题

**自动放行的请求弹窗闪一下又消失，是 bug 吗？**
不是。Paseo 0.8.0 里请求一到原生审批 UI 立刻出现，插件只能事后经 `respondToPermission` 消掉，所以闪的时长恒等于决策耗时（面板每行都标了毫秒数）。规则/学习/缓存命中的毫秒级即决，基本不闪；走顾问网络的一批会闪。SDK 目前没有同步拦截口，有了我们就接。

**一定要用 OpenRouter 吗？**
不用。默认后端是 OpenCode Zen 免费版。OpenRouter（`https://openrouter.ai/api/alpha/decisions` + `typesafe/jev-1.13`）仍是支持的备选项，任意 Decisions-API 兼容服务都行。

**规则为什么在 Add 时就被拒？**
编辑器跑的和保存时同一套语义校验：最常见的是命令里写了 `*`（那里按字面匹配——换子串或`/正则/`）、后端/能力拼写错误、allow/ask 规则零匹配条件。

**这条是谁判的？**
最近决策每行都署名（`via Jev`、`via Laya`、`via Jev+Laya`），理由字符串永远归属实际干活的顾问，不会挂错名字。
