import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runAudit } from "../dist/audit.js";
import { diffSnapshot, loadSnapshot, renderSnapshot, takeSnapshot } from "../dist/diff.js";

let home: string;
let project: string;

function codexConfig(extraServer: boolean): string {
  return [
    "[mcp_servers.snyk]",
    'command = "npx"',
    'args = ["-y", "snyk@1.2.3", "mcp"]',
    ...(extraServer ? ["", "[mcp_servers.sneaky]", 'command = "npx"', 'args = ["-y", "sneaky@latest"]'] : []),
  ].join("\n");
}

function audit() {
  return runAudit({ home, projectPath: project, generatedAt: new Date().toISOString() });
}

beforeAll(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), "skopecreep-diff-"));
  project = path.join(home, "project");
  fs.mkdirSync(path.join(home, ".codex"), { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(path.join(home, ".codex", "config.toml"), codexConfig(false));
});

afterAll(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe("creep detection", () => {
  it("reports nothing new when posture is unchanged", () => {
    const creep = diffSnapshot(audit(), takeSnapshot(audit()));
    expect(creep.newFindings).toHaveLength(0);
    expect(creep.newInventoryKeys).toHaveLength(0);
    expect(creep.removedInventoryKeys).toHaveLength(0);
  });

  it("surfaces a new MCP server and its finding after the snapshot", () => {
    const snapshot = takeSnapshot(audit());
    fs.writeFileSync(path.join(home, ".codex", "config.toml"), codexConfig(true));
    const creep = diffSnapshot(audit(), snapshot);
    expect(creep.newInventoryKeys).toContain("mcp:codex/sneaky");
    expect(creep.newInventoryKeys).not.toContain("mcp:codex/snyk");
    expect(creep.newFindings.some((f) => f.ruleId === "mcp-unpinned-package")).toBe(true);
    // and the reverse direction: removing it shows up as removed
    fs.writeFileSync(path.join(home, ".codex", "config.toml"), codexConfig(false));
    const after = diffSnapshot(audit(), takeSnapshot(audit()));
    expect(after.newInventoryKeys).toHaveLength(0);
  });

  it("round-trips through renderSnapshot/loadSnapshot", () => {
    const p = path.join(home, "snap.json");
    fs.writeFileSync(p, renderSnapshot(audit()));
    const loaded = loadSnapshot(p);
    expect(loaded.schemaVersion).toBe(1);
    expect(diffSnapshot(audit(), loaded).newInventoryKeys).toHaveLength(0);
  });

  it("hard-errors on a missing or non-snapshot file", () => {
    expect(() => loadSnapshot(path.join(home, "nope.json"))).toThrow(/not found/);
    const p = path.join(home, "not-snap.json");
    fs.writeFileSync(p, '{"ignore": []}');
    expect(() => loadSnapshot(p)).toThrow(/not a skopecreep snapshot/);
  });
});
