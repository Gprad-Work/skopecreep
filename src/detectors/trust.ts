/** Over-broad trusted directories and disabled sandboxing (Codex-style). */
import * as path from "node:path";
import type { Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity, type Dim } from "../severity.js";
import { HOME, expandHome } from "../util.js";
import { makeFindingId } from "./util.js";

const HOME_SEGMENTS = HOME.split(path.sep).filter(Boolean).length;

function trustImpact(scope: string): Dim {
  const abs = path.resolve(expandHome(scope));
  if (abs === HOME) return 3;
  const seg = abs.split(path.sep).filter(Boolean).length;
  if (seg <= HOME_SEGMENTS + 1) return 2; // e.g. ~/Documents — a broad parent
  return 1; // a specific project directory
}

const UNSAFE_SANDBOX = new Set(["danger-full-access", "none", "disabled", "off"]);

export const detectTrust: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const g of inv.grants) {
    if (g.kind === "trusted-dir") {
      if (g.value.toLowerCase() !== "trusted" || !g.scope) continue;
      const impact = trustImpact(g.scope);
      if (impact <= 1) continue; // trusting one specific project is expected; don't nag
      findings.push({
        id: makeFindingId("broad-trusted-dir", [g.tool, g.scope]),
        ruleId: "broad-trusted-dir",
        tool: g.tool,
        severity: computeSeverity({ impact, exposure: 2, exploitability: 1 }),
        confidence: "high",
        title: `Broad directory trusted: ${g.scope}`,
        rationale:
          `${g.scope} is marked "trusted" (${g.source.path}). Trust on a broad parent directory extends reduced friction to ` +
          `every current and future project underneath it, including repos you clone later that could carry hostile agent instructions.`,
        remediation: {
          loose: `Replace the broad entry with trust entries for the specific project directories you actually work in.`,
          medium: `Remove the parent-directory trust and re-trust each project the first time you open it — a one-time prompt per repo.`,
          tight: `Remove it and keep new directories untrusted by default; before trusting a freshly cloned repo, skim its agent context files (CLAUDE.md, .cursorrules, hooks) first.`,
        },
        evidence: [{ path: g.source.path, locator: g.source.locator, redactedSnippet: `${g.scope} = trusted` }],
      });
    } else if (g.kind === "sandbox") {
      if (!UNSAFE_SANDBOX.has(g.value.toLowerCase())) continue;
      findings.push({
        id: makeFindingId("weak-sandbox", [g.tool, g.source.path, g.value]),
        ruleId: "weak-sandbox",
        tool: g.tool,
        severity: computeSeverity({ impact: 3, exposure: 2, exploitability: 2 }),
        confidence: "high",
        title: `Sandbox weakened: ${g.value}`,
        rationale:
          `Sandbox mode "${g.value}" (${g.source.path}) lets the agent read/write outside a confined workspace and reach the ` +
          `full filesystem/network, so any tool call — including injected ones — runs with your full user privileges.`,
        remediation: {
          loose: `Stop saving "${g.value}" as the default; pass it per invocation on the rare task that truly needs full access.`,
          medium: `Set the default to a confined mode (e.g. workspace-write) so the agent can edit the project but nothing outside it.`,
          tight: `Default to read-only with explicit escalation per task, and give full access only inside a container/VM.`,
        },
        evidence: [{ path: g.source.path, locator: g.source.locator, redactedSnippet: g.value }],
      });
    }
  }
  return findings;
};
