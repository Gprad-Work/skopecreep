/** JSON reporter — machine-readable, and guaranteed to omit raw file bodies. */
import type { AuditReport, Finding } from "../model.js";

export interface JsonOptions {
  findings: Finding[];
  suppressedCount: number;
  minSeverity: string;
}

export function renderJson(report: AuditReport, opts: JsonOptions): string {
  const inv = report.inventory;
  // Strip the in-memory `content` from every context source: reporters must
  // never write raw file bodies (which may hold anything) to disk/stdout.
  const contextSources = inv.contextSources.map(({ content, ...rest }) => rest);

  const out = {
    tool: "skopecreep",
    generatedAt: report.generatedAt,
    host: report.host,
    summary: {
      total: opts.findings.length,
      suppressed: opts.suppressedCount,
      minSeverity: opts.minSeverity,
      bySeverity: countBySeverity(opts.findings),
    },
    findings: opts.findings,
    inventory: {
      tools: inv.tools,
      mcpServers: inv.mcpServers,
      grants: inv.grants,
      hooks: inv.hooks,
      credentials: inv.credentials,
      capabilityDefs: inv.capabilityDefs,
      contextSources,
      errors: inv.errors,
    },
  };
  return JSON.stringify(out, null, 2);
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}
