/** Lifecycle hooks — auto-run commands on agent tool events. */
import * as path from "node:path";
import type { Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity } from "../severity.js";
import { makeFindingId } from "./util.js";
import { evidenceSnippet } from "../secrets/redact.js";

const NET_OR_OBFUSCATED =
  /curl|wget|\bnc\b|ncat|socat|ssh|scp|base64\s+(?:-d|--decode)|\beval\b|\|\s*(?:sh|bash|zsh)\b|https?:\/\//i;

/** Coding-agent CLIs a hook shouldn't be spawning: hook → agent → hook is a loop. */
const AGENT_BINARIES = new Set(["claude", "codex", "cursor-agent", "aider", "gemini", "copilot", "amp", "opencode"]);
/** Prefixes that wrap the real binary: `env FOO=1 claude`, `sudo claude`, … */
const WRAPPERS = new Set(["env", "sudo", "time", "nohup", "nice", "xargs", "command", "exec"]);

function segmentBinary(segment: string): string {
  const tokens = segment.trim().split(/\s+/);
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (t.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t) || WRAPPERS.has(path.basename(t).toLowerCase())) {
      i++;
      continue;
    }
    return path.basename(t).toLowerCase();
  }
  return "";
}

function invokesAgent(command: string): boolean {
  return command
    .split(/\s*(?:&&|\|\||[|;])\s*/)
    .some((seg) => AGENT_BINARIES.has(segmentBinary(seg)));
}

export const detectHooks: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const h of inv.hooks) {
    const agentRecursion = invokesAgent(h.command);
    if (agentRecursion) {
      // A Stop/session-end hook that re-invokes the agent is a straight loop;
      // on other events it still multiplies cost per tool call.
      const loop = h.event.toLowerCase().includes("stop");
      findings.push({
        id: makeFindingId("hook-agent-recursion", [h.tool, h.source.path, h.event, h.command]),
        ruleId: "hook-agent-recursion",
        tool: h.tool,
        severity: computeSeverity({ impact: 2, exposure: loop ? 3 : 2, exploitability: 2 }),
        confidence: "medium",
        title: `Hook on ${h.event} re-invokes a coding agent`,
        rationale:
          `A ${h.event} hook (${h.source.path}) runs \`${evidenceSnippet(h.command)}\`, which launches another agent session. ` +
          (loop
            ? `On a stop event this recurses — each run ends by starting the next, burning tokens until something external kills it.`
            : `Every matching event spawns a full agent run, multiplying cost and creating actions no human initiated.`),
        remediation: {
          loose: `Add an explicit guard to the hook (a depth/env-var check or a hard turn budget) so it cannot re-trigger itself.`,
          medium: `Remove the agent call from the hook and trigger follow-up runs deliberately (manually or via a scheduled job with a run limit).`,
          tight: `Remove it, and enforce spend/turn limits on the account so no config change can silently create an unbounded agent loop again.`,
        },
        evidence: [{ path: h.source.path, locator: h.source.locator, redactedSnippet: evidenceSnippet(h.command) }],
      });
    }

    const suspicious = NET_OR_OBFUSCATED.test(h.command);
    // The recursion finding already covers "this hook auto-runs a command" —
    // the generic lifecycle finding only adds signal when it's network/obfuscated.
    if (!agentRecursion || suspicious) {
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
          ? {
              loose: `Verify the network destination and payload are yours, and replace any piped-download (\`curl … | sh\`) with a local, reviewed script.`,
              medium: `Remove the network/decode step from the hook; keep hooks limited to local, version-controlled scripts.`,
              tight: `Delete the hook, audit what it has been sending/fetching, and re-add only a minimal local script with no network access.`,
            }
          : {
              loose: `Confirm the hook command is one you added and still want running on every ${h.event} event.`,
              medium: `Point the hook at a version-controlled script (not an inline one-liner) so changes to it are visible in diffs.`,
              tight: `Keep only hooks you actively rely on, each a reviewed local script with no network calls, and remove the rest.`,
            },
        evidence: [{ path: h.source.path, locator: h.source.locator, redactedSnippet: evidenceSnippet(h.command) }],
      });
    }
  }
  return findings;
};
