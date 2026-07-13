/** Broad shell-command allowlists (e.g. Codex prefix_rule allow entries). */
import * as path from "node:path";
import type { Finding } from "../model.js";
import { evidenceSnippet } from "../secrets/redact.js";
import { computeSeverity, type Dim } from "../severity.js";
import type { Detector } from "./types.js";
import { makeFindingId } from "./util.js";

// Direct code-execution binaries.
const HIGH = new Set([
  "bash",
  "sh",
  "zsh",
  "fish",
  "eval",
  "python",
  "python3",
  "node",
  "ruby",
  "perl",
  "php",
  "xargs",
  "env",
]);
// Network / cloud / packaging / encoding — powerful but not raw code-exec.
const MED = new Set([
  "curl",
  "wget",
  "ssh",
  "scp",
  "nc",
  "ncat",
  "socat",
  "az",
  "gcloud",
  "aws",
  "kubectl",
  "docker",
  "npm",
  "npx",
  "pip",
  "pip3",
  "make",
  "base64",
]);

function tierImpact(binary: string): Dim {
  if (HIGH.has(binary)) return 3;
  if (MED.has(binary)) return 2;
  return 0;
}

export const detectAllowlist: Detector = (inv) => {
  // group risky prefixes per source file
  const groups = new Map<string, { tool: Finding["tool"]; path: string; risky: { prefix: string; impact: Dim }[] }>();

  for (const g of inv.grants) {
    if (g.kind !== "allowlist-cmd") continue;
    const tokens = g.value.trim().split(/\s+/);
    const binary = path.basename(tokens[0] ?? "").toLowerCase();
    let impact = tierImpact(binary);
    if (impact === 0) continue;
    // A fully-specified command (fixed URL or several constraining args) is
    // much narrower than allowlisting the bare binary — pull it down a notch.
    const constrained = /https?:\/\//.test(g.value) || tokens.length >= 3;
    if (constrained) impact = Math.max(1, impact - 1) as Dim;

    const key = `${g.tool}|${g.source.path}`;
    if (!groups.has(key)) groups.set(key, { tool: g.tool, path: g.source.path, risky: [] });
    groups.get(key)!.risky.push({ prefix: g.value, impact });
  }

  const findings: Finding[] = [];
  for (const grp of groups.values()) {
    if (grp.risky.length === 0) continue;
    const maxImpact = grp.risky.reduce((m, r) => (r.impact > m ? r.impact : m), 0 as Dim);
    const listed = grp.risky
      .slice()
      .sort((a, b) => b.impact - a.impact)
      .slice(0, 8)
      .map((r) => evidenceSnippet(r.prefix, 60));
    findings.push({
      id: makeFindingId("broad-cmd-allowlist", [grp.tool, grp.path]),
      ruleId: "broad-cmd-allowlist",
      tool: grp.tool,
      severity: computeSeverity({ impact: maxImpact, exposure: 2, exploitability: 2 }),
      confidence: "medium",
      title: `${grp.risky.length} shell command(s) auto-allowed without confirmation`,
      rationale:
        `${grp.path} allowlists command prefix(es) that run without a prompt, including: ${listed.join(", ")}. ` +
        `Auto-allowed network/exec commands are a direct exfiltration and code-execution path if the agent is misled.`,
      remediation: {
        loose: `Constrain each risky prefix with its full arguments (a fixed URL, a fixed subcommand) instead of allowlisting the bare binary.`,
        medium: `Drop shell/interpreter and network binaries (bash, python, curl, ssh, cloud CLIs) from the allowlist; keep auto-allow for read-only commands only.`,
        tight: `Rebuild the allowlist from empty: add only fully-specified, side-effect-free commands as they prove routine, and let everything else prompt.`,
      },
      evidence: [{ path: grp.path, redactedSnippet: listed.join(" | ") }],
    });
  }
  return findings;
};
