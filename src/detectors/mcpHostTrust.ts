/** MCP exposure: remote servers on unknown (non-mainstream) hosts or plain-HTTP transport. */
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

function isLoopback(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.startsWith("127.")) return true; // whole 127.0.0.0/8 block is loopback
  // ::1 in compressed or expanded form (0:0:0:0:0:0:0:1, 0000:...:0001)
  return h === "::1" || /^(?:0+:){2,7}0*1$/.test(h);
}

export const detectMcpHostTrust: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const s of inv.mcpServers) {
    if (s.transport === "stdio" || !s.host) continue;

    // Plain HTTP to a non-loopback host: tool definitions and session data
    // (often including auth headers) cross the network readable and mutable.
    if (s.url?.toLowerCase().startsWith("http://") && !isLoopback(s.host)) {
      findings.push({
        id: makeFindingId("mcp-insecure-transport", [s.tool, s.name, s.host]),
        ruleId: "mcp-insecure-transport",
        tool: s.tool,
        severity: computeSeverity({ impact: 2, exposure: 2, exploitability: 1 }),
        confidence: "high",
        title: `MCP server "${s.name}" uses unencrypted http:// to ${s.host}`,
        rationale:
          `"${s.name}" connects to ${s.url} over plain HTTP. Everything on that channel — the tool definitions the agent trusts, ` +
          `request/response data, any auth header — is readable and modifiable by anyone on the network path.`,
        remediation: {
          loose: `Confirm the host is on a network you fully control (e.g. a LAN service) and that no credentials ride on the connection.`,
          medium: `Switch the endpoint to https:// — if the server doesn't offer TLS, put it behind a reverse proxy that does.`,
          tight: `Use https with authentication, and tunnel to it (VPN/SSH) if the server lives on a network you don't control end-to-end.`,
        },
        evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: `${s.transport} → ${s.url}` }],
      });
    }

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
      remediation: {
        loose: `Confirm you trust ${s.host}, and keep per-use approval on for the tools it exposes.`,
        medium: `Switch to the provider's official first-party MCP endpoint if one exists; review this server's tool list before granting any auto-approval.`,
        tight: `Remove the server (or self-host an audited copy), and only reconnect third-party MCP endpoints after reviewing what they expose and pinning approvals per-tool.`,
      },
      evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: `${s.transport} → ${s.url}` }],
    });
  }
  return findings;
};
