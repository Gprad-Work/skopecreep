import { describe, it, expect } from "vitest";
import { detectMcpHostTrust } from "../../dist/detectors/mcpHostTrust.js";
import { inv, src } from "./helpers.js";
import type { MCPServer } from "../../dist/model.js";

function remoteServer(overrides: Partial<MCPServer>): MCPServer {
  return {
    tool: "claude-code",
    name: "server",
    transport: "http",
    host: "example.com",
    url: "https://example.com/mcp",
    envKeys: [],
    secretEnvKeys: [],
    hasSecretInEnv: false,
    source: src("settings.json"),
    ...overrides,
  };
}

describe("detectMcpHostTrust", () => {
  it("flags a remote server on an unrecognized host", () => {
    const findings = detectMcpHostTrust(inv({ mcpServers: [remoteServer({ host: "evil.example.com" })] }));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("mcp-unknown-remote-host");
  });

  it("does not flag a known first-party host (exact match)", () => {
    const findings = detectMcpHostTrust(inv({ mcpServers: [remoteServer({ host: "notion.com" })] }));
    expect(findings).toHaveLength(0);
  });

  it("does not flag a subdomain of a known first-party host", () => {
    const findings = detectMcpHostTrust(inv({ mcpServers: [remoteServer({ host: "mcp.notion.com" })] }));
    expect(findings).toHaveLength(0);
  });

  it("is case-insensitive when matching known hosts", () => {
    const findings = detectMcpHostTrust(inv({ mcpServers: [remoteServer({ host: "Notion.COM" })] }));
    expect(findings).toHaveLength(0);
  });

  it("does not flag a lookalike host that merely contains a known name", () => {
    // "notion.com.evil.example.com" is NOT a suffix match on "notion.com" and must still be flagged.
    const findings = detectMcpHostTrust(inv({ mcpServers: [remoteServer({ host: "notion.com.evil.example.com" })] }));
    expect(findings).toHaveLength(1);
  });

  it("skips stdio-transport servers entirely (no host to evaluate)", () => {
    const findings = detectMcpHostTrust(
      inv({
        mcpServers: [
          remoteServer({ transport: "stdio", host: undefined, url: undefined, command: "node", args: ["server.js"] }),
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });
});
