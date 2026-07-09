/** Human-readable terminal reporter. */
import pc from "picocolors";
import type { AuditReport, Finding, Severity, ToolId } from "../model.js";
import { SEVERITY_ORDER } from "../severity.js";

export interface TerminalOptions {
  findings: Finding[];
  suppressedCount: number;
  minSeverity: Severity;
}

function sevColor(s: Severity, text: string): string {
  switch (s) {
    case "critical":
      return pc.bgRed(pc.white(pc.bold(text)));
    case "high":
      return pc.red(pc.bold(text));
    case "medium":
      return pc.yellow(text);
    case "low":
      return pc.blue(text);
    default:
      return pc.dim(text);
  }
}

function badge(s: Severity): string {
  return sevColor(s, ` ${s.toUpperCase()} `);
}

function toolSummary(report: AuditReport, id: ToolId): string {
  const inv = report.inventory;
  const mcp = inv.mcpServers.filter((x) => x.tool === id).length;
  const grants = inv.grants.filter((x) => x.tool === id).length;
  const hooks = inv.hooks.filter((x) => x.tool === id).length;
  const ctx = inv.contextSources.filter((x) => x.tool === id).length;
  const creds = inv.credentials.filter((x) => x.tool === id).length;
  const parts = [`${mcp} MCP`, `${grants} grants`, `${hooks} hooks`, `${ctx} context`, `${creds} creds`];
  return pc.dim(parts.join(" · "));
}

export function renderTerminal(report: AuditReport, opts: TerminalOptions): string {
  const L: string[] = [];
  L.push("");
  L.push(`${pc.bold("skopecreep")} ${pc.dim("— AI tooling scope audit")}`);
  L.push(pc.dim(`scanned ${report.generatedAt} · platform ${report.host.platform}`));
  L.push("");

  // Tool inventory.
  L.push(pc.bold("Tools"));
  const nameW = Math.max(...report.inventory.tools.map((t) => t.displayName.length), 8);
  for (const t of report.inventory.tools) {
    const mark = t.installed ? pc.green("✓") : pc.dim("✗");
    const name = t.displayName.padEnd(nameW);
    const summary = t.installed ? toolSummary(report, t.id) : pc.dim("not installed");
    L.push(`  ${mark} ${name}  ${summary}`);
  }
  L.push("");

  // Findings.
  const counts = countBySeverity(opts.findings);
  const tally = SEVERITY_ORDER.filter((s) => counts[s])
    .map((s) => sevColor(s, `${counts[s]} ${s}`))
    .join(pc.dim(" · "));
  const suppressNote = opts.suppressedCount > 0 ? pc.dim(` (${opts.suppressedCount} suppressed by baseline)`) : "";
  L.push(`${pc.bold("Findings")} ${tally || pc.green("none")}${suppressNote}`);
  L.push("");

  if (opts.findings.length === 0) {
    L.push(pc.green(`  No findings at or above "${opts.minSeverity}" severity.`));
  } else {
    for (const f of opts.findings) {
      L.push(`${badge(f.severity)} ${pc.bold(f.title)}`);
      L.push(`  ${pc.dim(`${f.tool} · ${f.ruleId} · confidence ${f.confidence}`)}`);
      if (f.atlas && f.atlas.length > 0) {
        const tags = f.atlas
          .map((a) => `${a.techniqueId} ${a.techniqueName} (${a.tacticName})`)
          .join(pc.dim(", "));
        L.push(`  ${pc.dim("ATLAS:")} ${pc.magenta(tags)}`);
      }
      L.push(`  ${f.rationale}`);
      for (const e of f.evidence) {
        const loc = e.locator ? pc.dim(` (${e.locator})`) : "";
        L.push(`  ${pc.dim("↳")} ${pc.cyan(e.path)}${loc}`);
        if (e.redactedSnippet) L.push(`      ${pc.dim(e.redactedSnippet)}`);
      }
      L.push(`  ${pc.green("fix:")} ${f.remediation}`);
      L.push("");
    }
  }

  if (report.inventory.errors.length > 0) {
    L.push(pc.yellow(`Notes (${report.inventory.errors.length}):`));
    for (const err of report.inventory.errors) {
      L.push(pc.dim(`  · [${err.tool}] ${err.message}${err.path ? ` (${err.path})` : ""}`));
    }
    L.push("");
  }

  return L.join("\n");
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}
