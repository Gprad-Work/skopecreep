/** Secrets at rest: credential files, MCP env blocks, and secrets in context. */
import type { Finding } from "../model.js";
import { scanTextForSecrets } from "../secrets/patterns.js";
import { fingerprint } from "../secrets/redact.js";
import { computeSeverity, type Dim, exposureFromFile } from "../severity.js";
import type { Detector } from "./types.js";
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
      remediation: {
        loose: `Make the file owner-only (chmod 600) and keep it out of git repos and cloud-synced folders.${
          c.inVcsOrSyncedDir || c.worldOrGroupReadable
            ? " This one is already exposed (git/synced dir or readable by others) — rotate it now regardless of which tier you pick."
            : ""
        }`,
        medium: `Rotate the credential, then keep the replacement in an OS keychain or secret manager and delete the plaintext file (many tools support keychain-backed auth).`,
        tight: `Rotate it, store the replacement only in a secret manager, and add secret scanning (pre-commit/CI) so a credential can't sit in plaintext again.`,
      },
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
      remediation: {
        loose: `Restrict the config file to owner-only perms and make sure it's ignored by git/cloud sync.`,
        medium: `Replace the inline value with an environment-variable reference (e.g. \${${s.secretEnvKeys[0] ?? "VAR"}}) so the config file holds no secret.`,
        tight: `Move the secret to a secret manager, inject it into the server's environment at launch, and rotate the currently-inlined value.`,
      },
      evidence: [
        {
          path: s.source.path,
          locator: s.source.locator,
          redactedSnippet: `secret env keys: ${s.secretEnvKeys.join(", ")}`,
        },
      ],
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
      remediation: {
        loose: `Remove the secret from the ${ctx.role} file (reference an environment variable if the agent needs it) — and assume it has already traveled, so rotation is still the safe call.`,
        medium: `Remove it and rotate the credential — context files get shared, synced, and committed, so assume it has traveled.`,
        tight: `Remove, rotate, and add a pre-commit secret scanner so credentials can't land in context files (or any file) again.`,
      },
      evidence: [{ path: ctx.path, redactedSnippet: fingerprint(matches[0]!) }],
    });
  }

  return findings;
};
