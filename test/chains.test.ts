import { describe, expect, it } from "vitest";
import { correlateChains } from "../dist/chains.js";
import type { Finding } from "../dist/model.js";

let n = 0;
function f(ruleId: string, over: Partial<Finding> = {}): Finding {
  n += 1;
  return {
    id: `id${n}`,
    ruleId,
    tool: "codex",
    severity: "medium",
    confidence: "high",
    title: `${ruleId} title`,
    rationale: "r",
    remediation: { loose: "l", medium: "m", tight: "t" },
    evidence: [{ path: `/p/${ruleId}`, locator: "x" }],
    atlas: [],
    ...over,
  };
}

describe("correlateChains", () => {
  it("fires unattended-code-execution when a gate and a code path coexist on one tool", () => {
    const chains = correlateChains([f("weak-sandbox"), f("mcp-shell-server")]);
    const chain = chains.find((c) => c.ruleId === "chain-unattended-code-execution");
    expect(chain).toBeDefined();
    expect(chain?.related).toHaveLength(2);
  });

  it("escalates one severity step above the worst link", () => {
    const chains = correlateChains([
      f("weak-sandbox", { severity: "high" }),
      f("mcp-shell-server", { severity: "medium" }),
    ]);
    expect(chains[0]?.severity).toBe("critical"); // high → critical
  });

  it("takes the weakest link's confidence", () => {
    const chains = correlateChains([
      f("weak-sandbox", { confidence: "high" }),
      f("mcp-shell-server", { confidence: "medium" }),
    ]);
    expect(chains[0]?.confidence).toBe("medium");
  });

  it("does NOT fire when only one group is present", () => {
    expect(correlateChains([f("weak-sandbox"), f("auto-approve")])).toHaveLength(0); // both in the gate group only
  });

  it("does NOT chain across different tools", () => {
    const chains = correlateChains([
      f("weak-sandbox", { tool: "codex" }),
      f("mcp-shell-server", { tool: "claude-code" }),
    ]);
    expect(chains.some((c) => c.ruleId === "chain-unattended-code-execution")).toBe(false);
  });

  it("fires injection-to-exfiltration only with all three ingredients", () => {
    const two = correlateChains([f("context-injection"), f("secret-at-rest")]);
    expect(two.some((c) => c.ruleId === "chain-injection-to-exfiltration")).toBe(false);
    const three = correlateChains([f("context-injection"), f("secret-at-rest"), f("broad-cmd-allowlist")]);
    const chain = three.find((c) => c.ruleId === "chain-injection-to-exfiltration");
    expect(chain).toBeDefined();
    expect(chain?.related).toHaveLength(3);
  });

  it("fires tamperable-config for a writable config feeding an auto-run path", () => {
    const chains = correlateChains([f("world-writable-config"), f("lifecycle-hook")]);
    expect(chains.some((c) => c.ruleId === "chain-tamperable-agent-config")).toBe(true);
  });

  it("unions member ATLAS techniques and produces a stable id", () => {
    const members = [
      f("weak-sandbox", {
        atlas: [{ tacticId: "T", tacticName: "T", techniqueId: "AML.T0053", techniqueName: "x", url: "u" }],
      }),
      f("mcp-shell-server", {
        atlas: [{ tacticId: "T2", tacticName: "T2", techniqueId: "AML.T0011.001", techniqueName: "y", url: "u2" }],
      }),
    ];
    const a = correlateChains(members);
    const b = correlateChains(members);
    expect(a[0]?.id).toBe(b[0]?.id); // deterministic
    expect(a[0]?.atlas?.map((x) => x.techniqueId).sort()).toEqual(["AML.T0011.001", "AML.T0053"]);
  });

  it("returns nothing for an empty or unrelated finding set", () => {
    expect(correlateChains([])).toHaveLength(0);
    expect(correlateChains([f("mcp-unknown-remote-host")])).toHaveLength(0);
  });
});
