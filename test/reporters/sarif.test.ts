import { describe, expect, it } from "vitest";
import type { Finding } from "../../dist/model.js";
import { renderSarif } from "../../dist/reporters/sarif.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "abc123",
    ruleId: "weak-sandbox",
    tool: "codex",
    severity: "high",
    confidence: "high",
    title: "Sandbox weakened",
    rationale: "Full access everywhere.",
    remediation: { loose: "L fix", medium: "M fix", tight: "T fix" },
    evidence: [{ path: "/home/u/.codex/config.toml", locator: "sandbox_mode", redactedSnippet: "danger" }],
    atlas: [
      {
        tacticId: "AML.TA0005",
        tacticName: "Execution",
        techniqueId: "AML.T0053",
        techniqueName: "AI Agent Tool Invocation",
        url: "https://atlas.mitre.org/techniques/AML.T0053",
      },
    ],
    ...overrides,
  };
}

const report = {
  generatedAt: "2026-01-01T00:00:00Z",
  host: { platform: "linux" },
  inventory: {} as never,
  findings: [],
};

function render(findings: Finding[], projectPath?: string) {
  return JSON.parse(renderSarif(report, { findings, suppressedCount: 0, minSeverity: "info", projectPath }));
}

describe("renderSarif", () => {
  it("emits a valid SARIF 2.1.0 envelope with the tool driver", () => {
    const s = render([finding({})]);
    expect(s.version).toBe("2.1.0");
    expect(s.$schema).toContain("sarif-2.1.0");
    expect(s.runs[0].tool.driver.name).toBe("skopecreep");
    expect(s.runs[0].tool.driver.semanticVersion).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("dedupes rules by ruleId and keeps ruleIndex integrity", () => {
    const s = render([finding({ id: "a" }), finding({ id: "b" }), finding({ id: "c", ruleId: "auto-approve" })]);
    const rules = s.runs[0].tool.driver.rules;
    expect(rules.map((r: { id: string }) => r.id)).toEqual(["weak-sandbox", "auto-approve"]);
    for (const r of s.runs[0].results) {
      expect(rules[r.ruleIndex].id).toBe(r.ruleId);
    }
  });

  it("maps severity to level and GitHub security-severity", () => {
    const s = render([finding({ severity: "critical" }), finding({ id: "x", ruleId: "r2", severity: "low" })]);
    const [crit, low] = s.runs[0].results;
    expect(crit.level).toBe("error");
    expect(low.level).toBe("note");
    const rules = s.runs[0].tool.driver.rules;
    expect(rules[0].properties["security-severity"]).toBe("9.5");
    expect(rules[1].properties["security-severity"]).toBe("3.0");
  });

  it("includes all three remediation tiers in rule help and ATLAS ids in tags", () => {
    const s = render([finding({})]);
    const rule = s.runs[0].tool.driver.rules[0];
    expect(rule.help.text).toContain("loose: L fix");
    expect(rule.help.text).toContain("medium: M fix");
    expect(rule.help.text).toContain("tight: T fix");
    expect(rule.properties.tags).toContain("AML.T0053");
  });

  it("relativizes evidence under the project path and keeps home-dir paths absolute", () => {
    const s = render(
      [
        finding({ evidence: [{ path: "/repo/proj/.mcp.json", locator: "mcpServers.x" }] }),
        finding({ id: "y", ruleId: "r2", evidence: [{ path: "/home/u/.codex/auth.json" }] }),
      ],
      "/repo/proj",
    );
    const [inRepo, inHome] = s.runs[0].results;
    expect(inRepo.locations[0].physicalLocation.artifactLocation.uri).toBe(".mcp.json");
    expect(inRepo.locations[0].physicalLocation.artifactLocation.uriBaseId).toBe("PROJECTROOT");
    expect(inHome.locations[0].physicalLocation.artifactLocation.uri).toBe("file:///home/u/.codex/auth.json");
  });

  it("parses 'line N' locators into a region and carries the stable finding id as a fingerprint", () => {
    const s = render([finding({ evidence: [{ path: "/p/f.md", locator: "line 12" }] })]);
    const r = s.runs[0].results[0];
    expect(r.locations[0].physicalLocation.region.startLine).toBe(12);
    expect(r.partialFingerprints["skopecreepFindingId/v1"]).toBe("abc123");
  });
});
