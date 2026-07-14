/** Detector registry — runs every rule, dedupes, and severity-sorts findings. */

import { atlasForRule } from "../atlas.js";
import type { Finding, Inventory } from "../model.js";
import { severityRank } from "../severity.js";
import { detectAllowlist } from "./allowlist.js";
import { detectContextInjection } from "./contextInjection.js";
import { detectFileHygiene } from "./fileHygiene.js";
import { detectHooks } from "./hooks.js";
import { detectMcpHostTrust } from "./mcpHostTrust.js";
import { detectMcpSupplyChain } from "./mcpSupplyChain.js";
import { detectPermissions } from "./permissions.js";
import { detectSecrets } from "./secrets.js";
import { detectTrust } from "./trust.js";
import type { Detector } from "./types.js";

export const DETECTORS: Detector[] = [
  detectSecrets,
  detectMcpSupplyChain,
  detectMcpHostTrust,
  detectPermissions,
  detectTrust,
  detectAllowlist,
  detectHooks,
  detectContextInjection,
  detectFileHygiene,
];

export function runDetectors(inv: Inventory): Finding[] {
  const seen = new Set<string>();
  const all: Finding[] = [];
  for (const detect of DETECTORS) {
    let findings: Finding[] = [];
    try {
      findings = detect(inv);
    } catch (e) {
      inv.errors.push({ tool: "generic", message: `detector failed: ${(e as Error).message}` });
    }
    for (const f of findings) {
      if (seen.has(f.id)) continue;
      seen.add(f.id);
      all.push({ ...f, atlas: atlasForRule(f.ruleId) });
    }
  }
  return sortFindings(all);
}

/** Severity-desc, then tool, then ruleId — the canonical report order. */
export function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) => {
    const d = severityRank(b.severity) - severityRank(a.severity);
    if (d !== 0) return d;
    return a.tool.localeCompare(b.tool) || a.ruleId.localeCompare(b.ruleId);
  });
}
