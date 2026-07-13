import { describe, expect, it } from "vitest";
import { detectMcpHostTrust } from "../../dist/detectors/mcpHostTrust.js";
import type { MCPServer } from "../../dist/model.js";
import { inv, src } from "./helpers.js";

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

  it("flags plain http:// to a non-loopback host as insecure transport", () => {
    const findings = detectMcpHostTrust(
      inv({
        mcpServers: [remoteServer({ host: "internal.corp.example.com", url: "http://internal.corp.example.com/mcp" })],
      }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-insecure-transport")).toBe(true);
  });

  it("flags insecure transport even when the host is a known first-party provider", () => {
    const findings = detectMcpHostTrust(
      inv({ mcpServers: [remoteServer({ host: "mcp.notion.com", url: "http://mcp.notion.com/mcp" })] }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-insecure-transport")).toBe(true);
    expect(findings.some((f) => f.ruleId === "mcp-unknown-remote-host")).toBe(false);
  });

  it("does not flag http:// to localhost", () => {
    const findings = detectMcpHostTrust(
      inv({ mcpServers: [remoteServer({ host: "localhost", url: "http://localhost:3845/mcp" })] }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-insecure-transport")).toBe(false);
  });

  it("does not flag http:// to 127.0.0.1", () => {
    const findings = detectMcpHostTrust(
      inv({ mcpServers: [remoteServer({ host: "127.0.0.1", url: "http://127.0.0.1:8080/mcp" })] }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-insecure-transport")).toBe(false);
  });

  it("treats the whole 127/8 block and expanded IPv6 loopback as loopback", () => {
    for (const host of ["127.0.0.2", "[0:0:0:0:0:0:0:1]"]) {
      const findings = detectMcpHostTrust(
        inv({ mcpServers: [remoteServer({ host, url: `http://${host}:8080/mcp` })] }),
      );
      expect(
        findings.some((f) => f.ruleId === "mcp-insecure-transport"),
        `flagged loopback ${host}`,
      ).toBe(false);
    }
  });

  it("does not flag https:// URLs as insecure transport", () => {
    const findings = detectMcpHostTrust(inv({ mcpServers: [remoteServer({ host: "evil.example.com" })] }));
    expect(findings.some((f) => f.ruleId === "mcp-insecure-transport")).toBe(false);
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
