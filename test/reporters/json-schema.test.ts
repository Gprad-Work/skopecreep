/**
 * Guards the published JSON contract (schema/skopecreep-report.v1.schema.json)
 * against silent drift — without an external validator dependency. This is a
 * structural check of the invariants the schema promises: required keys at
 * each level, the schemaVersion const, enum'd severities, three-tier
 * remediation, and the no-raw-content rule for context sources.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Finding } from "../../dist/model.js";
import { emptyInventory } from "../../dist/model.js";
import { renderJson } from "../../dist/reporters/json.js";

const schemaPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "schema",
  "skopecreep-report.v1.schema.json",
);
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

function sampleReport() {
  const inv = emptyInventory();
  inv.contextSources.push({
    tool: "claude-code",
    role: "instructions",
    path: "/p/CLAUDE.md",
    sha256: "deadbeef",
    sizeBytes: 10,
    content: "SHOULD NEVER BE SERIALIZED",
  });
  const finding: Finding = {
    id: "f1",
    ruleId: "weak-sandbox",
    tool: "codex",
    severity: "high",
    confidence: "high",
    title: "t",
    rationale: "r",
    remediation: { loose: "l", medium: "m", tight: "t" },
    evidence: [{ path: "/p/x", locator: "line 1", redactedSnippet: "s" }],
    atlas: [
      {
        tacticId: "AML.TA0005",
        tacticName: "Execution",
        techniqueId: "AML.T0053",
        techniqueName: "AI Agent Tool Invocation",
        url: "https://atlas.mitre.org/techniques/AML.T0053",
      },
    ],
  };
  return {
    generatedAt: "2026-01-01T00:00:00Z",
    host: { platform: "linux" },
    inventory: inv,
    findings: [finding],
  };
}

describe("JSON report contract (schemaVersion 1)", () => {
  const out = JSON.parse(
    renderJson(sampleReport() as never, { findings: sampleReport().findings, suppressedCount: 0, minSeverity: "info" }),
  );

  it("carries schemaVersion 1 and every top-level required key from the schema", () => {
    expect(out.schemaVersion).toBe(schema.properties.schemaVersion.const);
    for (const key of schema.required) {
      expect(out, `missing top-level key "${key}"`).toHaveProperty(key);
    }
  });

  it("findings carry every required key, including three-tier remediation", () => {
    const required: string[] = schema.$defs.finding.required;
    for (const key of required) expect(out.findings[0]).toHaveProperty(key);
    for (const tier of schema.$defs.finding.properties.remediation.required) {
      expect(typeof out.findings[0].remediation[tier]).toBe("string");
    }
    expect(schema.$defs.severity.enum).toContain(out.findings[0].severity);
  });

  it("inventory carries every required section and never serializes context bodies", () => {
    for (const key of schema.properties.inventory.required) {
      expect(out.inventory, `missing inventory section "${key}"`).toHaveProperty(key);
    }
    expect(out.inventory.contextSources[0]).not.toHaveProperty("content");
    expect(JSON.stringify(out)).not.toContain("SHOULD NEVER BE SERIALIZED");
  });
});
