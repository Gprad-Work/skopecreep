import { describe, it, expect } from "vitest";
import * as os from "node:os";
import * as path from "node:path";
import { detectTrust } from "../../dist/detectors/trust.js";
import { inv, src } from "./helpers.js";

const HOME = os.homedir();

describe("detectTrust", () => {
  it("flags trusting the home directory itself (highest impact)", () => {
    const findings = detectTrust(
      inv({
        grants: [{ tool: "codex", kind: "trusted-dir", value: "trusted", scope: HOME, source: src("config.toml") }],
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("broad-trusted-dir");
  });

  it("flags a broad parent one level under home (e.g. ~/Documents)", () => {
    const findings = detectTrust(
      inv({
        grants: [
          {
            tool: "codex",
            kind: "trusted-dir",
            value: "trusted",
            scope: path.join(HOME, "Documents"),
            source: src("config.toml"),
          },
        ],
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("broad-trusted-dir");
  });

  it("does not flag trusting a specific project directory deep under home", () => {
    const findings = detectTrust(
      inv({
        grants: [
          {
            tool: "codex",
            kind: "trusted-dir",
            value: "trusted",
            scope: path.join(HOME, "code", "my-project"),
            source: src("config.toml"),
          },
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag a non-trusted value", () => {
    const findings = detectTrust(
      inv({
        grants: [{ tool: "codex", kind: "trusted-dir", value: "untrusted", scope: HOME, source: src("config.toml") }],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("flags an unsafe sandbox mode", () => {
    const findings = detectTrust(
      inv({
        grants: [{ tool: "codex", kind: "sandbox", value: "danger-full-access", source: src("config.toml") }],
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("weak-sandbox");
  });

  it("does not flag a confined sandbox mode", () => {
    const findings = detectTrust(
      inv({
        grants: [{ tool: "codex", kind: "sandbox", value: "workspace-write", source: src("config.toml") }],
      }),
    );
    expect(findings).toHaveLength(0);
  });
});
