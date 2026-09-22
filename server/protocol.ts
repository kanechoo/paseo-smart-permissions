/** Local structural mirrors of the Paseo protocol permission types.
 *  Rationale: the daemon compiles the plugin checkout without node_modules and
 *  only maps the plugin SDK + zod, so any other bare import fails install-time
 *  `checkSourceImports` ("Could not resolve type dependency"). See
 *  tests/packaging.test.ts. These mirrors are intentionally shape-identical;
 *  local `tsc` (which still sees the real package in devDependencies) verifies
 *  assignability both ways at dev time. Mirrors protocol 0.8.0. */
export type AgentProvider = string;
export interface AgentMetadata {
  [key: string]: unknown;
}
export type AgentPermissionRequestKind = "tool" | "plan" | "question" | "mode" | "other";
export type AgentPermissionUpdate = AgentMetadata;
export interface AgentPermissionAction {
  id: string;
  label: string;
  behavior: "allow" | "deny";
  variant?: "primary" | "secondary" | "danger";
  intent?: "implement" | "implement_resume" | "dismiss";
}
export type ToolCallDetail = {
  type: "shell";
  command: string;
  cwd?: string;
  output?: string;
  exitCode?: number | null;
} | {
  type: "read";
  filePath: string;
  content?: string;
  offset?: number;
  limit?: number;
} | {
  type: "edit";
  filePath: string;
  oldString?: string;
  newString?: string;
  unifiedDiff?: string;
} | {
  type: "write";
  filePath: string;
  content?: string;
} | {
  type: "search";
  query: string;
  toolName?: "search" | "grep" | "glob" | "web_search";
  content?: string;
  filePaths?: string[];
  webResults?: Array<{
    title: string;
    url: string;
  }>;
  annotations?: string[];
  numFiles?: number;
  numMatches?: number;
  durationMs?: number;
  durationSeconds?: number;
  truncated?: boolean;
  mode?: "content" | "files_with_matches" | "count";
} | {
  type: "fetch";
  url: string;
  prompt?: string;
  result?: string;
  code?: number;
  codeText?: string;
  bytes?: number;
  durationMs?: number;
} | {
  type: "worktree_setup";
  worktreePath: string;
  branchName: string;
  log: string;
  commands: Array<{
    index: number;
    command: string;
    cwd: string;
    log: string;
    status: "running" | "completed" | "failed";
    exitCode: number | null;
    durationMs?: number;
  }>;
  truncated?: boolean;
} | {
  type: "sub_agent";
  subAgentType?: string;
  description?: string;
  childSessionId?: string;
  log: string;
  actions?: Array<{
    index: number;
    toolName: string;
    summary?: string;
  }>;
} | {
  type: "plain_text";
  label?: string;
  text?: string;
} | {
  type: "plan";
  text: string;
} | {
  type: "unknown";
  input: unknown;
  output: unknown;
};
export interface AgentPermissionRequest {
  id: string;
  provider: AgentProvider;
  name: string;
  kind: AgentPermissionRequestKind;
  title?: string;
  description?: string;
  input?: AgentMetadata;
  detail?: ToolCallDetail;
  suggestions?: AgentPermissionUpdate[];
  actions?: AgentPermissionAction[];
  metadata?: AgentMetadata;
}
export type AgentPermissionResponse = {
  behavior: "allow";
  selectedActionId?: string;
  updatedInput?: AgentMetadata;
  updatedPermissions?: AgentPermissionUpdate[];
} | {
  behavior: "deny";
  selectedActionId?: string;
  message?: string;
  interrupt?: boolean;
};
