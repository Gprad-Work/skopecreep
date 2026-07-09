import { describe, it, expect } from "vitest";
import { ATLAS_TECHNIQUES, RULE_ATLAS_MAP, atlasForRule } from "../dist/atlas.js";
import { runAudit } from "../dist/audit.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const detectorsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "detectors");

/** Every ruleId any detector actually declares, found by scanning the built detector sources. */
function allKnownRuleIds(): Set<string> {
  const ids = new Set<string>();
  for (const file of fs.readdirSync(detectorsDir)) {
    if (!file.endsWith(".js") || file === "index.js" || file === "util.js") continue;
    const src = fs.readFileSync(path.join(detectorsDir, file), "utf8");
    for (const m of src.matchAll(/ruleId:\s*"([^"]+)"/g)) ids.add(m[1]!);
  }
  return ids;
}

describe("ATLAS mapping", () => {
  it("maps every rule to at least one known technique", () => {
    for (const [ruleId, techIds] of Object.entries(RULE_ATLAS_MAP)) {
      expect(techIds.length, `${ruleId} has no technique ids`).toBeGreaterThan(0);
      for (const id of techIds) {
        expect(ATLAS_TECHNIQUES[id], `${ruleId} references unknown technique ${id}`).toBeDefined();
      }
    }
  });

  it("returns a non-empty, deduped list for every mapped rule", () => {
    for (const ruleId of allKnownRuleIds()) {
      const refs = atlasForRule(ruleId);
      expect(refs.length, `atlasForRule(${ruleId}) is empty`).toBeGreaterThan(0);
      const keys = refs.map((r) => `${r.tacticId}|${r.techniqueId}`);
      expect(new Set(keys).size).toBe(keys.length);
      for (const r of refs) {
        expect(r.url).toMatch(/^https:\/\/atlas\.mitre\.org\/techniques\/AML\.T\d/);
      }
    }
  });

  it("returns an empty list for an unknown rule id", () => {
    expect(atlasForRule("not-a-real-rule")).toEqual([]);
  });

  it("every ruleId a detector can emit has an ATLAS mapping (no rule left unmapped)", () => {
    const declared = allKnownRuleIds();
    expect(declared.size).toBeGreaterThan(0);
    for (const ruleId of declared) {
      expect(RULE_ATLAS_MAP[ruleId], `${ruleId} is emitted by a detector but missing from RULE_ATLAS_MAP`).toBeDefined();
    }
  });
});

describe("ATLAS attachment on real findings", () => {
  let home: string;
  let project: string;

  it("every finding from a real audit carries a non-empty atlas mapping", () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "skopecreep-atlas-"));
    project = path.join(home, "project");
    fs.mkdirSync(project, { recursive: true });
    fs.mkdirSync(path.join(home, ".codex"), { recursive: true });
    fs.writeFileSync(
      path.join(home, ".codex", "config.toml"),
      ['approval_policy = "never"', 'sandbox_mode = "danger-full-access"'].join("\n"),
    );

    const report = runAudit({ home, projectPath: project, generatedAt: "2026-01-01T00:00:00Z" });
    expect(report.findings.length).toBeGreaterThan(0);
    for (const f of report.findings) {
      expect(f.atlas, `finding ${f.ruleId} missing atlas mapping`).toBeDefined();
      expect(f.atlas!.length, `finding ${f.ruleId} has empty atlas mapping`).toBeGreaterThan(0);
    }

    fs.rmSync(home, { recursive: true, force: true });
  });
});
