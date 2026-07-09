/**
 * Mapping from skopecreep rules to the MITRE ATLAS matrix
 * (https://atlas.mitre.org/matrices/ATLAS) — the ATT&CK-style knowledge base
 * of adversary tactics/techniques against AI systems.
 *
 * skopecreep audits static configuration, not runtime behavior, so a rule is
 * mapped to the technique that the *misconfiguration enables* (e.g. an
 * unpinned MCP package enables AML.T0010.001, not "is" that technique).
 * Every rule in DETECTORS must have an entry here — enforced by
 * test/atlas.test.ts.
 */

export interface AtlasTactic {
  id: string;
  name: string;
}

export interface AtlasTechnique {
  id: string;
  name: string;
  tactics: AtlasTactic[];
}

const TA = {
  initialAccess: { id: "AML.TA0004", name: "Initial Access" },
  execution: { id: "AML.TA0005", name: "Execution" },
  persistence: { id: "AML.TA0006", name: "Persistence" },
  defenseEvasion: { id: "AML.TA0007", name: "Defense Evasion" },
  discovery: { id: "AML.TA0008", name: "Discovery" },
  exfiltration: { id: "AML.TA0010", name: "Exfiltration" },
  impact: { id: "AML.TA0011", name: "Impact" },
  privilegeEscalation: { id: "AML.TA0012", name: "Privilege Escalation" },
  credentialAccess: { id: "AML.TA0013", name: "Credential Access" },
} as const satisfies Record<string, AtlasTactic>;

/** Techniques this tool's rules actually map to. Not the full ATLAS matrix. */
export const ATLAS_TECHNIQUES = {
  "AML.T0010": {
    id: "AML.T0010",
    name: "AI Supply Chain Compromise",
    tactics: [TA.initialAccess],
  },
  "AML.T0010.001": {
    id: "AML.T0010.001",
    name: "AI Supply Chain Compromise: AI Software",
    tactics: [TA.initialAccess],
  },
  "AML.T0010.002": {
    id: "AML.T0010.002",
    name: "AI Supply Chain Compromise: Data",
    tactics: [TA.initialAccess],
  },
  "AML.T0011.001": {
    id: "AML.T0011.001",
    name: "User Execution: Malicious Package",
    tactics: [TA.execution],
  },
  "AML.T0025": {
    id: "AML.T0025",
    name: "Exfiltration via Cyber Means",
    tactics: [TA.exfiltration],
  },
  "AML.T0034.002": {
    id: "AML.T0034.002",
    name: "Cost Harvesting: Agentic Resource Consumption",
    tactics: [TA.impact],
  },
  "AML.T0050": {
    id: "AML.T0050",
    name: "Command and Scripting Interpreter",
    tactics: [TA.execution],
  },
  "AML.T0051.001": {
    id: "AML.T0051.001",
    name: "LLM Prompt Injection: Indirect",
    tactics: [TA.execution],
  },
  "AML.T0053": {
    id: "AML.T0053",
    name: "AI Agent Tool Invocation",
    tactics: [TA.execution, TA.privilegeEscalation],
  },
  "AML.T0055": {
    id: "AML.T0055",
    name: "Unsecured Credentials",
    tactics: [TA.credentialAccess],
  },
  "AML.T0056": {
    id: "AML.T0056",
    name: "Extract LLM System Prompt",
    tactics: [TA.exfiltration],
  },
  "AML.T0057": {
    id: "AML.T0057",
    name: "LLM Data Leakage",
    tactics: [TA.exfiltration],
  },
  "AML.T0061": {
    id: "AML.T0061",
    name: "LLM Prompt Self-Replication",
    tactics: [TA.persistence],
  },
  "AML.T0068": {
    id: "AML.T0068",
    name: "LLM Prompt Obfuscation",
    tactics: [TA.defenseEvasion],
  },
  "AML.T0069.002": {
    id: "AML.T0069.002",
    name: "Discover LLM System Information: System Prompt",
    tactics: [TA.discovery],
  },
} as const satisfies Record<string, AtlasTechnique>;

export type AtlasTechniqueId = keyof typeof ATLAS_TECHNIQUES;

/** ruleId -> one or more ATLAS technique IDs, most-relevant first. */
export const RULE_ATLAS_MAP: Record<string, AtlasTechniqueId[]> = {
  "secret-at-rest": ["AML.T0055"],
  "secret-in-mcp-env": ["AML.T0055"],
  "secret-in-context": ["AML.T0055", "AML.T0057"],
  "mcp-unpinned-package": ["AML.T0010.001"],
  "mcp-shell-server": ["AML.T0050"],
  "mcp-remote-code-source": ["AML.T0011.001", "AML.T0010.001"],
  "mcp-unknown-remote-host": ["AML.T0010.001"],
  "mcp-insecure-transport": ["AML.T0010.001", "AML.T0025"],
  "broad-permission": ["AML.T0053"],
  "permission-bypass-mode": ["AML.T0053"],
  "auto-approve": ["AML.T0053"],
  "broad-trusted-dir": ["AML.T0053"],
  "weak-sandbox": ["AML.T0053"],
  "broad-cmd-allowlist": ["AML.T0053"],
  "lifecycle-hook": ["AML.T0050"],
  "hook-agent-recursion": ["AML.T0034.002"],
  "context-injection": ["AML.T0051.001"],
  "context-self-replication": ["AML.T0061", "AML.T0051.001"],
  "context-system-prompt-probe": ["AML.T0056", "AML.T0069.002"],
  "context-hidden-unicode": ["AML.T0068"],
  "context-base64-blob": ["AML.T0068"],
  "context-external-dep": ["AML.T0010.002"],
  "world-writable-config": ["AML.T0010"],
};

export interface AtlasRef {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  url: string;
}

function techniqueUrl(id: string): string {
  return `https://atlas.mitre.org/techniques/${id}`;
}

/** Every (tactic, technique) pair a rule maps to, deduped, tactic-then-technique ordered. */
export function atlasForRule(ruleId: string): AtlasRef[] {
  const ids = RULE_ATLAS_MAP[ruleId] ?? [];
  const out: AtlasRef[] = [];
  const seen = new Set<string>();
  for (const techId of ids) {
    const tech = ATLAS_TECHNIQUES[techId];
    for (const tactic of tech.tactics) {
      const key = `${tactic.id}|${tech.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        tacticId: tactic.id,
        tacticName: tactic.name,
        techniqueId: tech.id,
        techniqueName: tech.name,
        url: techniqueUrl(tech.id),
      });
    }
  }
  return out;
}
