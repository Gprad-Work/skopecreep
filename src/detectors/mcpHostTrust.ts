/** MCP exposure: remote servers pointing at unknown (non-mainstream) hosts. */
import type { Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity } from "../severity.js";
import { makeFindingId } from "./util.js";

/** Widely-used, first-party SaaS MCP hosts. Matched by exact or suffix. */
const KNOWN_HOSTS = [
  "claude.ai",
  "anthropic.com",
  "notion.com",
  "atlassian.com",
  "atlassian.net",
  "githubcopilot.com",
  "github.com",
  "linear.app",
  "stripe.com",
  "sentry.io",
  "openai.com",
  "microsoft.com",
  "office.com",
  "sharepoint.com",
  "slack.com",
  "figma.com",
  "datadoghq.com",
  "snowflakecomputing.com",
  "airtable.com",
  "amplitude.com",
  "semrush.com",
  "cloudflare.com",
];

function isKnownHost(host: string): boolean {
  const h = host.toLowerCase();
  return KNOWN_HOSTS.some((k) => h === k || h.endsWith("." + k));
}

export const detectMcpHostTrust: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const s of inv.mcpServers) {
    if (s.transport === "stdio" || !s.host) continue;
    if (isKnownHost(s.host)) continue; // first-party SaaS → inventory only, not a finding
    findings.push({
      id: makeFindingId("mcp-unknown-remote-host", [s.tool, s.name, s.host]),
      ruleId: "mcp-unknown-remote-host",
      tool: s.tool,
      severity: computeSeverity({ impact: 2, exposure: 1, exploitability: 1 }),
      confidence: "medium",
      title: `MCP server "${s.name}" talks to an unrecognized remote host (${s.host})`,
      rationale:
        `"${s.name}" connects to ${s.url}. This host isn't a recognized first-party MCP provider, so its tool definitions and ` +
        `data handling aren't independently vetted — the remote can also change the tools it offers at any time.`,
      remediation: `Confirm you trust ${s.host}. Prefer official/first-party MCP endpoints, and review the tools it exposes before enabling auto-approval.`,
      evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: `${s.transport} → ${s.url}` }],
    });
  }
  return findings;
};
