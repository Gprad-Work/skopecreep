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

  it("flags a server run from a github: shorthand with no commit pin", () => {
    const findings = detectMcpSupplyChain(
      inv({ mcpServers: [stdioServer({ command: "npx", args: ["-y", "github:someuser/mcp-server"] })] }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-remote-code-source")).toBe(true);
  });

  it("flags a server installed from a git+https URL on a branch", () => {
    const findings = detectMcpSupplyChain(
      inv({ mcpServers: [stdioServer({ command: "uvx", args: ["--from", "git+https://github.com/someuser/mcp.git@main", "mcp"] })] }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-remote-code-source")).toBe(true);
  });

  it("does not flag a remote code source pinned to a commit SHA", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({ command: "uvx", args: ["--from", "git+https://github.com/someuser/mcp.git@0f4c9a1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a", "mcp"] }),
        ],
      }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-remote-code-source")).toBe(false);
  });

  it("does not double-flag a github: spec as unpinned-package (remote-code-source owns it)", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({
            command: "npx",
            args: ["-y", "github:someuser/mcp-server"],
            packageSpec: "github:someuser/mcp-server",
            pinned: false,
          }),
        ],
      }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-remote-code-source")).toBe(true);
    expect(findings.some((f) => f.ruleId === "mcp-unpinned-package")).toBe(false);
  });

  it("does not flag a SHA-pinned github: spec as unpinned-package either", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({
            command: "npx",
            args: ["-y", "github:someuser/mcp-server#0f4c9a1"],
            packageSpec: "github:someuser/mcp-server#0f4c9a1",
            pinned: false,
          }),
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("is not fooled by an incidental hex token elsewhere on the command line", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({
            command: "npx",
            args: ["-y", "github:someuser/mcp-server", "--session", "@deadbeef1234"],
          }),
        ],
      }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-remote-code-source")).toBe(true);
  });

  it("uses the full scoped package name in the unpinned-package loose fix", () => {
    const findings = detectMcpSupplyChain(
      inv({
        mcpServers: [
          stdioServer({
            command: "npx",
            args: ["-y", "@scope/server@latest"],
            packageSpec: "@scope/server@latest",
            pinned: false,
          }),
        ],
      }),
    );
    const f = findings.find((x) => x.ruleId === "mcp-unpinned-package");
    expect(f?.remediation.loose).toContain('"@scope/server@1"');
  });

  it("does not flag a plain registry package as a remote code source", () => {
    const findings = detectMcpSupplyChain(
      inv({ mcpServers: [stdioServer({ command: "npx", args: ["-y", "snyk@1.2.3", "mcp"], packageSpec: "snyk@1.2.3", pinned: true })] }),
    );
    expect(findings.some((f) => f.ruleId === "mcp-remote-code-source")).toBe(false);
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
