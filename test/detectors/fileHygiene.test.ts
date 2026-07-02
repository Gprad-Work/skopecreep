import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { detectFileHygiene } from "../../dist/detectors/fileHygiene.js";
import { inv } from "./helpers.js";
import type { Tool } from "../../dist/model.js";

let dir: string;

function file(name: string, mode: number): string {
  const full = path.join(dir, name);
  fs.writeFileSync(full, "{}");
  fs.chmodSync(full, mode);
  return full;
}

function tool(configPaths: string[]): Tool {
  return { id: "claude-code", displayName: "Claude Code", installed: true, configPaths };
}

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "skopecreep-filehygiene-"));
});

afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("detectFileHygiene", () => {
  it("flags a world-writable config file", () => {
    if (process.platform === "win32") return; // POSIX perm bits aren't meaningful on Windows.
    const p = file("world-writable.json", 0o666);
    const findings = detectFileHygiene(inv({ tools: [tool([p])] }));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("world-writable-config");
  });

  it("does not flag an owner-only config file", () => {
    if (process.platform === "win32") return;
    const p = file("owner-only.json", 0o600);
    const findings = detectFileHygiene(inv({ tools: [tool([p])] }));
    expect(findings).toHaveLength(0);
  });

  it("groups multiple config paths for one tool into a single finding, listing only the writable ones", () => {
    if (process.platform === "win32") return;
    const safe = file("safe.json", 0o600);
    const writable = file("writable.json", 0o666);
    const findings = detectFileHygiene(inv({ tools: [tool([safe, writable])] }));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toHaveLength(1);
    expect(findings[0]?.evidence[0]?.path).toBe(writable);
  });

  it("returns no findings when no tools are installed", () => {
    expect(detectFileHygiene(inv({ tools: [] }))).toHaveLength(0);
  });
});
