/**
 * Attack-chain correlation.
 *
 * Detectors score each misconfiguration in isolation. But a machine's real
 * risk is often compositional: three separate `medium` findings — an agent
 * that runs code with no confirmation, an MCP server that pulls untrusted
 * code, and a plaintext secret — chain into a critical, hands-off
 * read-secret-and-run-anything scenario. This pass runs after detectors,
 * matches curated chain patterns against the finding set, and emits one
 * synthesized finding per matched chain, escalated one severity step above
 * its worst link.
 *
 * Kept deliberately conservative (calibration over coverage): chains are
 * tool-scoped (every link is the same agent's config), each pattern's groups
 * are disjoint so a chain always has distinct members, and the chain is only
 * as confident as its least-confident link.
 */
import type { AtlasRef } from "./atlas.js";
import { makeFindingId } from "./detectors/util.js";
import type { Confidence, Finding, Remediation, ToolId } from "./model.js";
import { maxSeverity, nextSeverityUp } from "./severity.js";

interface ChainPattern {
  id: string;
  title: string;
  /** Each group must contribute ≥1 finding (OR within a group, AND across groups). Groups are disjoint. */
  groups: string[][];
  /** Builds the rationale from the concrete links that matched. */
  rationale: (linkTitles: string[]) => string;
  remediation: Remediation;
}

const CHAINS: ChainPattern[] = [
  {
    id: "chain-unattended-code-execution",
    title: "Unattended code execution: no confirmation gate + an untrusted code path",
    groups: [
      // A human gate has been removed.
      ["permission-bypass-mode", "auto-approve", "weak-sandbox", "broad-permission", "broad-cmd-allowlist"],
      // …and there's a way for untrusted or mutable code to enter and run.
      ["mcp-shell-server", "mcp-unpinned-package", "mcp-remote-code-source", "lifecycle-hook", "hook-agent-recursion"],
    ],
    rationale: (links) =>
      `This agent both runs actions without a confirmation gate and exposes a path for untrusted or changeable code to execute: ${links.join("; ")}. ` +
      `Individually each is a misconfiguration; together they are an unattended-RCE chain — a hijacked package, a poisoned tool, or an injected instruction runs with your privileges and nothing stops to ask.`,
    remediation: {
      loose: `Break the chain at its cheapest link — usually restoring the confirmation prompt (drop the bypass/auto-approve default) is a one-line change that neutralizes the whole scenario.`,
      medium: `Fix the confirmation gate AND confine the code path (pin the package, run the server binary directly, or remove the hook) so no single regression re-opens the chain.`,
      tight: `Resolve every link, and run this agent in a sandbox/VM with per-use approval so a future misconfiguration can't compose into unattended execution again.`,
    },
  },
  {
    id: "chain-injection-to-exfiltration",
    title: "Injection-to-exfiltration: attacker-controllable context + a secret + an auto-approved egress path",
    groups: [
      ["context-injection", "context-self-replication", "context-hidden-unicode", "context-external-dep"],
      ["secret-at-rest", "secret-in-mcp-env", "secret-in-context"],
      ["broad-cmd-allowlist", "auto-approve", "broad-permission", "mcp-shell-server", "permission-bypass-mode"],
    ],
    rationale: (links) =>
      `This agent has all three ingredients of a self-serve exfiltration path: injectable instructions, a readable secret, and an auto-approved way to run network/shell commands — ${links.join("; ")}. ` +
      `An attacker who controls the context file can have the agent read the secret and send it out, with no human in the loop.`,
    remediation: {
      loose: `Cut one ingredient — moving the secret into a keychain/secret manager (so there's nothing on disk to read) is usually the least disruptive break.`,
      medium: `Remove the secret from plaintext AND require confirmation on network/shell tools, so an injected instruction has neither something to steal nor a way to send it.`,
      tight: `Resolve every link: rotate and vault the secret, require per-use approval for egress, and treat the flagged context file as untrusted until reviewed.`,
    },
  },
  {
    id: "chain-tamperable-agent-config",
    title: "Tamperable trust: world-writable config feeding something the agent auto-executes",
    groups: [
      ["world-writable-config"],
      ["broad-trusted-dir", "auto-approve", "permission-bypass-mode", "lifecycle-hook", "mcp-shell-server"],
    ],
    rationale: (links) =>
      `Another local user or process can edit this agent's configuration, and the agent auto-trusts or auto-executes what that configuration says: ${links.join("; ")}. ` +
      `That turns a file-permission slip into a local privilege-escalation path — someone edits the config, the agent runs it for you.`,
    remediation: {
      loose: `Lock the writable config down (chmod go-w / 600) — the fastest single break.`,
      medium: `Restrict the file perms AND narrow what the agent auto-executes (remove the broad trust or the auto-run hook), so a future perms mistake doesn't re-arm it.`,
      tight: `Owner-only perms on all agent config, no broad auto-trust, and confirmation on auto-run paths — so tampering can't translate into execution.`,
    },
  },
];

/** Union member atlas refs, deduped by technique id, so a chain carries its links' techniques. */
function unionAtlas(members: Finding[]): AtlasRef[] {
  const seen = new Set<string>();
  const out: AtlasRef[] = [];
  for (const m of members) {
    for (const a of m.atlas ?? []) {
      const key = `${a.tacticId}|${a.techniqueId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(a);
    }
  }
  return out;
}

const CONF_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

/** A chain is only as trustworthy as its weakest link. */
function weakestConfidence(members: Finding[]): Confidence {
  return members.map((m) => m.confidence).reduce((a, b) => (CONF_RANK[a] <= CONF_RANK[b] ? a : b), "high");
}

/** Correlate a single tool's findings into any matching chains. */
function chainsForTool(tool: ToolId, findings: Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const pattern of CHAINS) {
    const perGroup = pattern.groups.map((group) => findings.filter((f) => group.includes(f.ruleId)));
    if (perGroup.some((g) => g.length === 0)) continue; // a group had no link → no chain

    // Members = all matched links, deduped (groups are disjoint, so this is just a flatten).
    const members = [...new Map(perGroup.flat().map((f) => [f.id, f])).values()];
    const worst = members.reduce<Finding["severity"]>((s, m) => maxSeverity(s, m.severity), "info");
    const linkTitles = members.map((m) => `${m.title} (${m.ruleId})`);
    out.push({
      id: makeFindingId(pattern.id, [tool, ...members.map((m) => m.id).sort()]),
      ruleId: pattern.id,
      tool,
      severity: nextSeverityUp(worst),
      confidence: weakestConfidence(members),
      title: pattern.title,
      rationale: pattern.rationale(linkTitles),
      remediation: pattern.remediation,
      evidence: members.map((m) => ({
        path: m.evidence[0]?.path ?? "",
        locator: m.evidence[0]?.locator,
        redactedSnippet: `link: ${m.ruleId} — ${m.title}`,
      })),
      atlas: unionAtlas(members),
      related: members.map((m) => m.id).sort(),
    });
  }
  return out;
}

/**
 * Given the flat, deduped finding list, return synthesized chain findings
 * (never mutates the inputs). Callers merge these into the finding list and
 * re-sort.
 */
export function correlateChains(findings: Finding[]): Finding[] {
  const byTool = new Map<ToolId, Finding[]>();
  for (const f of findings) {
    const arr = byTool.get(f.tool) ?? [];
    arr.push(f);
    byTool.set(f.tool, arr);
  }
  const chains: Finding[] = [];
  for (const [tool, group] of byTool) chains.push(...chainsForTool(tool, group));
  return chains;
}
