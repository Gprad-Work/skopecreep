/**
 * Normalized data model.
 *
 * Every collector maps a tool's raw config into these shapes, and every
 * detector operates ONLY on these shapes. That decoupling is what lets us add
 * a new tool by writing one collector, and add a new check by writing one
 * detector, without either knowing about the other.
 */
import type { AtlasRef } from "./atlas.js";

export type ToolId = "claude-code" | "codex" | "cursor" | "windsurf" | "copilot" | "generic";

export const ALL_TOOL_IDS: ToolId[] = ["claude-code", "codex", "cursor", "windsurf", "copilot", "generic"];

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

/** A pointer back to where evidence lives on disk. Never contains a secret. */
export interface SourceRef {
  path: string;
  /** e.g. "mcp_servers.snyk-security" or "line 12" */
  locator?: string;
}

export interface Tool {
  id: ToolId;
  displayName: string;
  installed: boolean;
  configPaths: string[];
  notes?: string[];
}

export type McpTransport = "stdio" | "sse" | "http";

export interface MCPServer {
  tool: ToolId;
  name: string;
  transport: McpTransport;
  /** stdio only */
  command?: string;
  args?: string[];
  /** sse / http only */
  url?: string;
  host?: string;
  /** names only — values are never stored */
  envKeys: string[];
  /** subset of envKeys whose value looked like a secret */
  secretEnvKeys: string[];
  hasSecretInEnv: boolean;
  /** e.g. "snyk@latest" when command runs npx/uvx a package */
  packageSpec?: string;
  /** false when packageSpec is unpinned (@latest / no version) */
  pinned?: boolean;
  source: SourceRef;
}

export type GrantKind =
  | "permission-rule"
  | "trusted-dir"
  | "auto-approve"
  | "sandbox"
  | "allowlist-cmd"
  | "bypass-mode";

export interface CapabilityGrant {
  tool: ToolId;
  kind: GrantKind;
  /** the rule string, directory, flag value, or command prefix */
  value: string;
  /** what the grant applies to (e.g. a path) */
  scope?: string;
  source: SourceRef;
}

export interface Hook {
  tool: ToolId;
  event: string;
  command: string;
  source: SourceRef;
}

export type ContextRole = "instructions" | "rule" | "memory" | "agent" | "skill";

export interface ContextSource {
  tool: ToolId;
  role: ContextRole;
  path: string;
  sha256: string;
  sizeBytes: number;
  /**
   * Loaded body, kept in memory for injection scanning only. Reporters MUST
   * strip this before writing anything to disk/stdout.
   */
  content: string;
}

export interface CredentialAtRest {
  tool: ToolId;
  path: string;
  /** e.g. "oauth-token", "api-key", "jwt", "private-key" */
  kind: string;
  /** octal string like "600" or "unknown" (Windows) */
  perms: string;
  worldOrGroupReadable: boolean;
  inVcsOrSyncedDir: boolean;
  /** redacted, e.g. "jwt ****a1b2 (len 812, entropy 5.4)"; never the raw value */
  redactedFingerprint: string;
  source: SourceRef;
}

export interface CapabilityDef {
  tool: ToolId;
  kind: "agent" | "skill" | "plugin";
  name: string;
  /** tool names this def grants, e.g. ["*"] or ["Bash", "Read"] */
  grantedTools: string[];
  source: SourceRef;
}

export interface Evidence {
  path: string;
  locator?: string;
  /** always passed through redaction */
  redactedSnippet?: string;
}

/**
 * Three graded fixes per finding, so the reader picks their own point on the
 * security/friction curve instead of being handed one absolute.
 */
export interface Remediation {
  /** lowest-friction mitigation — keeps the current workflow, trims the risk */
  loose: string;
  /** the balanced fix most users should apply */
  medium: string;
  /** maximum lockdown — strictest posture, most workflow friction */
  tight: string;
}

/** Render order for remediation tiers — reporters iterate this, never hardcode. */
export const REMEDIATION_TIERS = ["loose", "medium", "tight"] as const satisfies readonly (keyof Remediation)[];

export interface Finding {
  /** stable fingerprint for baselining */
  id: string;
  ruleId: string;
  tool: ToolId;
  severity: Severity;
  confidence: Confidence;
  title: string;
  rationale: string;
  remediation: Remediation;
  evidence: Evidence[];
  /**
   * MITRE ATLAS (https://atlas.mitre.org/matrices/ATLAS) tactic/technique
   * mapping for ruleId. Detectors don't set this — runDetectors attaches it
   * to every finding, so it's always populated by the time a report sees it.
   */
  atlas?: AtlasRef[];
}

/** Reserved for the call-history fast-follow (v0.2). */
export interface CallRecord {
  tool: ToolId;
  mcpServer?: string;
  toolName: string;
  ts?: string;
  source: SourceRef;
}

export interface CollectorError {
  tool: ToolId;
  path?: string;
  message: string;
}

export interface Inventory {
  tools: Tool[];
  mcpServers: MCPServer[];
  grants: CapabilityGrant[];
  hooks: Hook[];
  contextSources: ContextSource[];
  credentials: CredentialAtRest[];
  capabilityDefs: CapabilityDef[];
  callRecords: CallRecord[];
  errors: CollectorError[];
}

export function emptyInventory(): Inventory {
  return {
    tools: [],
    mcpServers: [],
    grants: [],
    hooks: [],
    contextSources: [],
    credentials: [],
    capabilityDefs: [],
    callRecords: [],
    errors: [],
  };
}

export interface AuditReport {
  generatedAt: string;
  host: { platform: string };
  inventory: Inventory;
  findings: Finding[];
}
