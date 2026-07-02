/** Top-level orchestration: collect inventory, run detectors, assemble report. */
import type { AuditReport, ToolId } from "./model.js";
import { collectAll } from "./collectors/index.js";
import { runDetectors } from "./detectors/index.js";

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
  return {
    generatedAt: opts.generatedAt,
    host: { platform: process.platform },
    inventory,
    findings,
  };
}
