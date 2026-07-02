/** Config files that are group/world-writable — a config-tampering vector. */
import type { Finding, ToolId } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity } from "../severity.js";
import { statInfo } from "../util.js";
import { makeFindingId } from "./util.js";

export const detectFileHygiene: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const tool of inv.tools) {
    const writable: string[] = [];
    for (const p of tool.configPaths) {
      const st = statInfo(p);
      if (st?.worldOrGroupWritable) writable.push(`${p} (${st.perms})`);
    }
    if (writable.length === 0) continue;
    findings.push({
      id: makeFindingId("world-writable-config", [tool.id, ...writable]),
      ruleId: "world-writable-config",
      tool: tool.id as ToolId,
      severity: computeSeverity({ impact: 2, exposure: 3, exploitability: 1 }),
      confidence: "high",
      title: `${tool.displayName} config is writable by other users`,
      rationale:
        `These ${tool.displayName} config files are group/world-writable, so another local user or process can silently ` +
        `edit them to add MCP servers, hooks, or instructions the agent will then trust: ${writable.join(", ")}.`,
      remediation: `Restrict the files to owner-only (chmod go-w), and prefer 600 for anything containing config the agent trusts.`,
      evidence: writable.map((w) => ({ path: w.split(" (")[0]!, redactedSnippet: w })),
    });
  }
  return findings;
};
