/** Secrets at rest: credential files, MCP env blocks, and secrets in context. */
import type { Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity, exposureFromFile, type Dim } from "../severity.js";
import { scanTextForSecrets } from "../secrets/patterns.js";
import { fingerprint } from "../secrets/redact.js";
import { exposureForPath, makeFindingId } from "./util.js";

const HIGH_VALUE_KINDS = new Set([
  "oauth-token",
  "private-key",
  "aws-access-key",
  "openai-key",
  "anthropic-key",
  "google-api-key",
  "github-token",
  "slack-token",
]);

function credImpact(kind: string): Dim {
  if (HIGH_VALUE_KINDS.has(kind)) return 3;
  return 2; // high-entropy / unknown
}

export const detectSecrets: Detector = (inv) => {
  const findings: Finding[] = [];

  for (const c of inv.credentials) {
    const impact = credImpact(c.kind);
    const exposure = exposureFromFile(c);
    const exploitability: Dim = c.worldOrGroupReadable || c.inVcsOrSyncedDir ? 3 : 1;
    findings.push({
      id: makeFindingId("secret-at-rest", [c.tool, c.path]),
      ruleId: "secret-at-rest",
      tool: c.tool,
      severity: computeSeverity({ impact, exposure, exploitability }),
      confidence: c.kind === "high-entropy" ? "medium" : "high",
      title: `Plaintext ${c.kind} stored on disk`,
      rationale:
        `${c.path} holds a ${c.kind} in plaintext (${c.redactedFingerprint}). ` +
        `File perms: ${c.perms}${c.inVcsOrSyncedDir ? "; inside a git/synced directory" : ""}. ` +
        `Anyone able to read this file inherits the associated access.`,
      remediation:
        `Rotate the credential, keep the file owner-only (chmod 600), and prefer an OS keychain or secret manager over a plaintext file. ` +
        `If it is in a git repo or cloud-synced folder, purge and rotate immediately.`,
      evidence: [{ path: c.path, redactedSnippet: c.redactedFingerprint }],
    });
  }

  for (const s of inv.mcpServers) {
    if (!s.hasSecretInEnv) continue;
    const exposure = exposureForPath(s.source.path);
    findings.push({
      id: makeFindingId("secret-in-mcp-env", [s.tool, s.source.path, s.name]),
      ruleId: "secret-in-mcp-env",
      tool: s.tool,
      severity: computeSeverity({ impact: 3, exposure, exploitability: 2 }),
      confidence: "medium",
      title: `MCP server "${s.name}" stores secret-looking values in its env block`,
      rationale:
        `The env for MCP server "${s.name}" (${s.source.path}) contains value(s) that look like secrets ` +
        `under key(s): ${s.secretEnvKeys.join(", ")}. Secrets in plaintext config are readable by any process/user with file access.`,
      remediation:
        `Reference the secret from an environment variable or secret manager instead of inlining it, and restrict file perms. ` +
        `Never commit MCP config containing secrets.`,
      evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: `secret env keys: ${s.secretEnvKeys.join(", ")}` }],
    });
  }

  for (const ctx of inv.contextSources) {
    if (!ctx.content) continue;
    const matches = scanTextForSecrets(ctx.content);
    if (matches.length === 0) continue;
    const exposure = exposureForPath(ctx.path);
    findings.push({
      id: makeFindingId("secret-in-context", [ctx.tool, ctx.path]),
      ruleId: "secret-in-context",
      tool: ctx.tool,
      severity: computeSeverity({ impact: 3, exposure, exploitability: exposure >= 3 ? 3 : 1 }),
      confidence: "high",
      title: `Secret embedded in ${ctx.role} file`,
      rationale:
        `${ctx.path} contains ${matches.length} secret-looking value(s), e.g. ${fingerprint(matches[0]!)}. ` +
        `Instruction/memory files are frequently shared, synced, or committed — a poor place for credentials.`,
      remediation: `Remove the secret from the ${ctx.role} file and rotate it. Keep credentials out of prompt/context files entirely.`,
      evidence: [{ path: ctx.path, redactedSnippet: fingerprint(matches[0]!) }],
    });
  }

  return findings;
};
