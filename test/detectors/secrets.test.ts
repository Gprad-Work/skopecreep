import { describe, it, expect } from "vitest";
import { detectSecrets } from "../../dist/detectors/secrets.js";
import { inv, src } from "./helpers.js";
import type { CredentialAtRest, MCPServer, ContextSource } from "../../dist/model.js";

const AWS = "AKIAIOSFODNN7EXAMPLE";

function cred(overrides: Partial<CredentialAtRest>): CredentialAtRest {
  return {
    tool: "codex",
    path: "/nonexistent-skopecreep-fixture/auth.json",
    kind: "aws-access-key",
    perms: "600",
    worldOrGroupReadable: false,
    inVcsOrSyncedDir: false,
    redactedFingerprint: "aws-access-key ****MPLE",
    source: src("auth.json"),
    ...overrides,
  };
}

describe("detectSecrets — credential at rest", () => {
  it("rates a safe-perms, non-VCS, high-value credential as medium", () => {
    const [f] = detectSecrets(inv({ credentials: [cred({})] }));
    expect(f?.ruleId).toBe("secret-at-rest");
    expect(f?.severity).toBe("medium");
  });

  it("escalates to critical when the credential is in a VCS/synced dir", () => {
    const [f] = detectSecrets(inv({ credentials: [cred({ inVcsOrSyncedDir: true })] }));
    expect(f?.severity).toBe("critical");
  });

  it("escalates to critical when the credential is world/group readable", () => {
    const [f] = detectSecrets(inv({ credentials: [cred({ worldOrGroupReadable: true, perms: "644" })] }));
    expect(f?.severity).toBe("critical");
  });

  it("treats unknown perms (e.g. Windows) as moderate exposure, not high", () => {
    const [f] = detectSecrets(inv({ credentials: [cred({ perms: "unknown" })] }));
    expect(f?.severity).toBe("medium");
  });

  it("uses medium confidence for a generic high-entropy kind, high confidence otherwise", () => {
    const [highEntropy] = detectSecrets(inv({ credentials: [cred({ kind: "high-entropy" })] }));
    const [known] = detectSecrets(inv({ credentials: [cred({ kind: "aws-access-key" })] }));
    expect(highEntropy?.confidence).toBe("medium");
    expect(known?.confidence).toBe("high");
  });
});

describe("detectSecrets — MCP env", () => {
  function mcpServer(overrides: Partial<MCPServer>): MCPServer {
    return {
      tool: "cursor",
      name: "withsecret",
      transport: "stdio",
      command: "node",
      args: ["server.js"],
      envKeys: ["API_TOKEN"],
      secretEnvKeys: ["API_TOKEN"],
      hasSecretInEnv: true,
      source: src("mcp.json"),
      ...overrides,
    };
  }

  it("flags an MCP server with a secret-looking env value", () => {
    const findings = detectSecrets(inv({ mcpServers: [mcpServer({})] }));
    expect(findings.some((f) => f.ruleId === "secret-in-mcp-env")).toBe(true);
  });

  it("does not flag an MCP server with no secret in env", () => {
    const findings = detectSecrets(
      inv({ mcpServers: [mcpServer({ hasSecretInEnv: false, secretEnvKeys: [] })] }),
    );
    expect(findings.some((f) => f.ruleId === "secret-in-mcp-env")).toBe(false);
  });
});

describe("detectSecrets — secret in context", () => {
  function ctx(overrides: Partial<ContextSource>): ContextSource {
    return {
      tool: "claude-code",
      role: "memory",
      path: "/nonexistent-skopecreep-fixture/memory/leak.md",
      sha256: "deadbeef",
      sizeBytes: 0,
      content: "",
      ...overrides,
    };
  }

  it("flags a context file containing a secret-looking value", () => {
    const findings = detectSecrets(inv({ contextSources: [ctx({ content: `Here is a key: ${AWS}` })] }));
    const f = findings.find((x) => x.ruleId === "secret-in-context");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("does not flag a context file with no secret-looking content", () => {
    const findings = detectSecrets(inv({ contextSources: [ctx({ content: "Just some project notes." })] }));
    expect(findings.some((f) => f.ruleId === "secret-in-context")).toBe(false);
  });

  it("does not flag an empty context file", () => {
    const findings = detectSecrets(inv({ contextSources: [ctx({ content: "" })] }));
    expect(findings).toHaveLength(0);
  });
});
