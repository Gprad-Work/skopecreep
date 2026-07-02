/** Lifecycle hooks — auto-run commands on agent tool events. */
import type { Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity } from "../severity.js";
import { makeFindingId } from "./util.js";
import { evidenceSnippet } from "../secrets/redact.js";

const NET_OR_OBFUSCATED =
  /curl|wget|\bnc\b|ncat|socat|ssh|scp|base64\s+(?:-d|--decode)|\beval\b|\|\s*(?:sh|bash|zsh)\b|https?:\/\//i;

export const detectHooks: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const h of inv.hooks) {
    const suspicious = NET_OR_OBFUSCATED.test(h.command);
    const severity = suspicious
      ? computeSeverity({ impact: 3, exposure: 3, exploitability: 3 })
      : computeSeverity({ impact: 1, exposure: 2, exploitability: 2 });
    findings.push({
      id: makeFindingId("lifecycle-hook", [h.tool, h.source.path, h.event, h.command]),
      ruleId: "lifecycle-hook",
      tool: h.tool,
      severity,
      confidence: suspicious ? "high" : "medium",
      title: suspicious
        ? `Hook on ${h.event} runs a network/obfuscated command`
        : `Hook runs a command on ${h.event}`,
      rationale: suspicious
        ? `A ${h.event} hook (${h.source.path}) executes \`${evidenceSnippet(h.command)}\`, which reaches the network or ` +
          `decodes/pipes a payload to a shell. Hooks run automatically and are an ideal persistence/exfiltration vector.`
        : `A ${h.event} hook (${h.source.path}) auto-runs \`${evidenceSnippet(h.command)}\` on every matching tool event. ` +
          `Even benign hooks are code you didn't approve per-run — worth confirming it's yours and does what you expect.`,
      remediation: suspicious
        ? `Remove or replace this hook. Never let a hook fetch remote code or pipe downloads into a shell.`
        : `Confirm the hook command is intentional and pinned; avoid hooks that call out to the network.`,
      evidence: [{ path: h.source.path, locator: h.source.locator, redactedSnippet: evidenceSnippet(h.command) }],
    });
  }
  return findings;
};
