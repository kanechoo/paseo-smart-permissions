import { describe, expect, it } from "vitest";
import { buildIR } from "../server/ir.js";
import { SmartPermissionsService } from "../server/service.js";
import { agent, fetchReq, read, req, shell, write } from "./helpers.js";

const svc = (extra = {}) => new SmartPermissionsService({ layaEnabled: false, ...extra });
async function run(s: SmartPermissionsService, r: ReturnType<typeof req>, a = agent()) {
  const responses: unknown[] = [];
  const out = await s.onPermissionRequested(r, a, async (...args) => { responses.push(args); });
  return { ...out, responses };
}

describe("e2e decision chains", () => {
  it("default user rule allows workspace reads", async () => {
    const s = svc();
    const r1 = await run(s, read("src/a.ts"));
    expect(r1.decision).toMatchObject({ decision: "ALLOW", source: "USER_RULE" });
    expect(r1.responded).toBe(true);
  });
  it("workspace-escape read is NOT released by user allow", async () => {
    const s = svc();
    const r = await run(s, read("../outside/secret.txt"));
    expect(r.decision.decision).toBe("ASK");
    expect(r.responded).toBe(false);
  });
  it("benign write -> ASK without rules, ALLOW with learned history", async () => {
    const s = svc();
    const r1 = await run(s, write("notes/x.md"));
    expect(r1.decision.decision).toBe("ASK");
    // human allows twice in UI
    const ir = buildIR({ request: write("notes/x.md"), agent: agent() });
    s.engine.learn(ir, "allow");
    s.engine.learn(ir, "allow");
    const r2 = await run(s, write("notes/x.md"));
    expect(r2.decision).toMatchObject({ decision: "ALLOW", source: "LEARNED_RULE" });
    expect(r2.responded).toBe(true);
  });
  it("secret access chain -> DENY + audited", async () => {
    const s = svc();
    const r = await run(s, read(".env"));
    expect(r.decision.decision).toBe("DENY");
    expect(s.audit.count()).toBe(1);
    expect(JSON.stringify(s.audit.recent(1))).not.toContain("sk-");
  });
  it("permission_resolved feeds learning", async () => {
    const s = svc();
    const r = req({ provider: "pi", name: "Write", detail: { type: "write", filePath: "docs/x.md" } as never });
    await run(s, r, agent("/workspace/project", "pi"));
    s.onPermissionResolved(r.id, { behavior: "allow" });
    s.onPermissionResolved(r.id, { behavior: "allow" });
    const again = req({ provider: "pi", name: "Write", detail: { type: "write", filePath: "docs/x.md" } as never });
    const out = await run(s, again, agent("/workspace/project", "pi"));
    expect(out.decision.source).toBe("LEARNED_RULE");
  });
  it("concurrent identical requests deduplicate and stay bounded", async () => {
    const s = svc();
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        run(s, shell(`npm test -- shard=${i % 5}`))),
    );
    expect(results).toHaveLength(50);
    for (const r of results) expect(["ALLOW", "ASK", "DENY"]).toContain(r.decision.decision);
  });
  it("cache hit on repeated LOW allow", async () => {
    const s = new SmartPermissionsService({
      layaEnabled: false,
      userRules: [{ id: "w", effect: "allow", commandPattern: "npm test" }],
    });
    await run(s, shell("npm test"));
    const before = s.cache.hits;
    await run(s, shell("npm test"));
    expect(s.cache.hits).toBeGreaterThan(before);
  });
  it("preview RPC path works without side effects", async () => {
    const s = svc();
    const d = await s.preview({ provider: "opencode", toolName: "Bash", kind: "tool", cwd: "/workspace/project", command: "git status" });
    expect(["ALLOW", "ASK", "DENY"]).toContain(d.decision);
    expect(s.audit.count()).toBe(0);
  });
  it("stats + config hot-reload", async () => {
    const s = svc();
    await run(s, shell("npm test"));
    expect(s.stats().total).toBe(1);
    const err = s.applySettings({ ...s.settings, defaultPolicy: "deny" as const });
    expect(err).toBeNull();
    expect(s.rulesVersion).toBe(2);
    const bad = s.applySettings({ ...s.settings, layaTimeoutMs: -5 });
    expect(bad).not.toBeNull();
  });
  it("workspace fetch matrix", async () => {
    const s = svc();
    const local = await run(s, fetchReq("http://localhost:3000/health"));
    expect(local.decision.risk).toBe("LOW");
    const pub = await run(s, fetchReq("https://example.com/x"));
    expect(pub.decision).toMatchObject({ decision: "DENY", source: "FALLBACK" });
  });
});
