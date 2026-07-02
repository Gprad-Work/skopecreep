/** MCP supply-chain: unpinned package runners and shell-as-server. */
import type { Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity } from "../severity.js";
import * as path from "node:path";
import { makeFindingId } from "./util.js";
import { evidenceSnippet } from "../secrets/redact.js";

const SHELLS = new Set(["bash", "sh", "zsh", "fish"]);

export const detectMcpSupplyChain: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const s of inv.mcpServers) {
    if (s.transport !== "stdio" || !s.command) continue;
    const cmdline = `${s.command} ${(s.args ?? []).join(" ")}`.trim();

    if (s.packageSpec && s.pinned === false) {
      findings.push({
        id: makeFindingId("mcp-unpinned-package", [s.tool, s.name, s.packageSpec]),
        ruleId: "mcp-unpinned-package",
        tool: s.tool,
        severity: computeSeverity({ impact: 3, exposure: 2, exploitability: 1 }),
        confidence: "high",
        title: `MCP server "${s.name}" auto-installs an unpinned package (${s.packageSpec})`,
        rationale:
          `"${s.name}" runs \`${evidenceSnippet(cmdline)}\`, which resolves "${s.packageSpec}" fresh from a public registry on every launch. ` +
          `An unpinned dependency means a compromised, hijacked, or typosquatted release would execute with your privileges inside the agent.`,
        remediation: `Pin the package to an exact version (and ideally a lockfile/integrity hash) instead of "@latest" or a bare name.`,
        evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: evidenceSnippet(cmdline) }],
      });
    }

    const base = path.basename(s.command).toLowerCase();
    if (SHELLS.has(base)) {
      findings.push({
        id: makeFindingId("mcp-shell-server", [s.tool, s.name]),
        ruleId: "mcp-shell-server",
        tool: s.tool,
        severity: computeSeverity({ impact: 3, exposure: 2, exploitability: 2 }),
        confidence: "high",
        title: `MCP server "${s.name}" is launched via a shell`,
        rationale:
          `"${s.name}" starts with \`${evidenceSnippet(cmdline)}\`. Running an MCP server through a shell (inline \`-c\`, piped scripts) ` +
          `is an easy vector for arbitrary command execution and obscures what actually runs.`,
        remediation: `Run the server binary directly with explicit args; avoid \`sh -c\`/\`bash -c\` wrappers.`,
        evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: evidenceSnippet(cmdline) }],
      });
    }
  }
  return findings;
};
