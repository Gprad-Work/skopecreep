/** Top-level orchestration: collect inventory, run detectors, assemble report. */

import { correlateChains } from "./chains.js";
import { collectAll } from "./collectors/index.js";
import { runDetectors, sortFindings } from "./detectors/index.js";
import type { AuditReport, ToolId } from "./model.js";

export interface AuditOptions {
  home: string;
  projectPath: string;
  tools?: ToolId[];
  /** caller supplies the timestamp (keeps this module deterministic/testable) */
  generatedAt: string;
}

export function runAudit(opts: AuditOptions): AuditReport {
  const inventory = collectAll({ home: opts.home, projectPath: opts.projectPath }, opts.tools);
  const findings = runDetectors(inventory);
  // Correlate the independent findings into attack chains, then re-sort so an
  // escalated chain surfaces above the individual links that compose it.
  const chains = correlateChains(findings);
  return {
    generatedAt: opts.generatedAt,
    host: { platform: process.platform },
    inventory,
    findings: chains.length > 0 ? sortFindings([...findings, ...chains]) : findings,
  };
}
