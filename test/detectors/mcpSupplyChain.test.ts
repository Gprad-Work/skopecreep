import { describe, it, expect } from "vitest";
import { detectMcpSupplyChain } from "../../dist/detectors/mcpSupplyChain.js";
import { inv, src } from "./helpers.js";
import type { MCPServer } from "../../dist/model.js";

function stdioServer(overrides: Partial<MCPServer>): MCPServer {
  return {
    tool: "codex",
    name: "server",
    transport: "stdio",
    command: "node",
    args: ["server.js"],
    envKeys: [],
    secretEnvKeys: [],
    hasSecretInEnv: false,
    source: src("config.toml"),
    ...overrides,
  };
}

describe("detectMcpSupplyChain", () => {
  it("flags an unpinned package spec", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({ command: "npx", args: ["-y", "snyk@latest", "mcp"], packageSpec: "snyk@latest", pinned: false }),
        ],
      }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-unpinned-package")).toBe(true);
  });

  it("does not flag a pinned package spec", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({ command: "npx", args: ["-y", "snyk@1.2.3", "mcp"], packageSpec: "snyk@1.2.3", pinned: true }),
        ],
      }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-unpinned-package")).toBe(false);
  });

  it("flags a server launched via a shell", () => {
    const findings = detectMcpSupplyChain(
      inv({ mcpServers: [stdioServer({ command: "/bin/bash", args: ["-c", "node server.js"] })] }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-shell-server")).toBe(true);
  });

  it("does not flag a direct binary invocation as a shell server", () => {
    const findings = detectMcpSupplyChain(inv({ mcpServers: [stdioServer({ command: "node" })] }));
    expect(findings.some((f) => f.ruleId === "mcp-shell-server")).toBe(false);
  });

  it("returns no findings for a pinned, non-shell, direct-binary server", () => {
    const findings = detectMcpSupplyChain(inv({ mcpServers: [stdioServer({ command: "node" })] }));
    expect(findings).toHaveLength(0);
  });

  it("can flag both unpinned-package and shell-server on the same entry", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({ command: "sh", args: ["-c", "npx -y snyk@latest mcp"], packageSpec: "snyk@latest", pinned: false }),
        ],
      }),
    );
    const ids = new Set(findings.map((f) => f.ruleId));
    expect(ids.has("mcp-unpinned-package")).toBe(true);
    expect(ids.has("mcp-shell-server")).toBe(true);
  });

  it("skips non-stdio transports entirely", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [stdioServer({ transport: "http", command: undefined, url: "https://example.com/mcp" })],
      }),
    );
    expect(findings).toHaveLength(0);
  });
});
