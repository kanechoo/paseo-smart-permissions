import type { AgentPermissionRequest } from "../server/protocol.js";
import type { AgentInfo } from "../server/service.js";

let seq = 0;
export function req(
  partial: Partial<AgentPermissionRequest> & { detail?: AgentPermissionRequest["detail"] },
): AgentPermissionRequest {
  seq += 1;
  return {
    id: `req-${seq}`,
    provider: "opencode",
    name: "Bash",
    kind: "tool",
    ...partial,
  } as AgentPermissionRequest;
}
export function agent(cwd = "/workspace/project", provider = "opencode"): AgentInfo {
  return { id: "agent-1", provider, cwd, workspaceId: "ws-1" };
}
export const shell = (command: string, provider = "opencode") =>
  req({ provider, name: "Bash", detail: { type: "shell", command } as never });
export const read = (filePath: string, provider = "opencode") =>
  req({ provider, name: "Read", detail: { type: "read", filePath } as never });
export const write = (filePath: string, provider = "opencode") =>
  req({ provider, name: "Write", detail: { type: "write", filePath } as never });
export const fetchReq = (url: string, provider = "codex") =>
  req({ provider, name: "Fetch", detail: { type: "fetch", url } as never });
