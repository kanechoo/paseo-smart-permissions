import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { SmartPermissionsService } from "../server/service.js";
import { agent, fetchReq, read, req, shell, write } from "./helpers.js";

/** One service per test keeps counts/cache isolated. Laya disabled -> deterministic. */
const svc = () => new SmartPermissionsService({ layaEnabled: false });
async function decide(svc_: SmartPermissionsService, r: ReturnType<typeof req>, a = agent()) {
  const calls: unknown[] = [];
  const out = await svc_.onPermissionRequested(r, a, async (...args) => { calls.push(args); });
  return { ...out, calls };
}

describe("providers: pi / opencode / codex / claude", () => {
  it("pi shell npm test -> LOW baseline, still ASK with advisors off", async () => {
    const { decision, calls } = await decide(svc(), shell("npm test", "pi"), agent("/workspace/project", "pi"));
    expect(decision.risk).toBe("LOW");
    expect(decision.decision).toBe("ASK"); // no advisor -> nothing auto-allows
    expect(calls).toHaveLength(0); // ASK = no respond call
  });
  it("opencode write in workspace -> ASK; user rule allows", async () => {
    const s = new SmartPermissionsService({
      layaEnabled: false,
      userRules: [{ id: "w", effect: "allow", provider: "opencode", capability: "file.write", pathPattern: "src/*.ts" }],
    });
    const { decision, calls } = await decide(s, write("src/a.ts", "opencode"));
    expect(decision).toMatchObject({ decision: "ALLOW", source: "USER_RULE" });
    expect(calls).toHaveLength(1);
  });
  it("codex fetch public url -> DENY fallback (HIGH, laya off)", async () => {
    const { decision, calls } = await decide(svc(), fetchReq("https://registry.example/pkg.tgz", "codex"), agent("/workspace/project", "codex"));
    expect(decision).toMatchObject({ decision: "DENY", source: "FALLBACK" });
    expect(calls).toHaveLength(1);
    expect((calls[0] as unknown[])[2]).toMatchObject({ behavior: "deny", interrupt: false });
  });
  it("claude edit outside workspace -> hard DENY", async () => {
    const r = req({ provider: "claude", name: "Edit", detail: { type: "edit", filePath: "/etc/hosts" } as never });
    const { decision } = await decide(svc(), r, agent("/workspace/project", "claude"));
    expect(decision.decision).toBe("DENY");
    expect(decision.source).toBe("HARD_RULE");
  });
  it("extends variants normalize (codex-third-party, claude-deepseek)", () => {
    const a = buildIR({ request: read("src/a.ts", "codex-third-party"), agent: agent("/w", "codex-third-party") });
    expect(a.provider).toBe("codex");
    const b = buildIR({ request: read("src/a.ts", "claude-deepseek"), agent: agent("/w", "claude-deepseek") });
    expect(b.provider).toBe("claude");
  });
  it("unknown provider stays safe (ASK without advisor)", async () => {
    const { decision } = await decide(svc(), shell("echo hi", "gemini-future"), agent("/workspace/project", "gemini-future"));
    expect(decision.decision).toBe("ASK");
  });
  it("disabled plugin never responds", async () => {
    const s = new SmartPermissionsService({ enabled: false });
    const { responded, calls } = await decide(s, shell("rm -rf /", "pi"));
    expect(responded).toBe(false);
    expect(calls).toHaveLength(0);
  });
});
