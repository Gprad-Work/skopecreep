import { describe, it, expect } from "vitest";
import { detectPermissions } from "../../dist/detectors/permissions.js";
import { inv, src } from "./helpers.js";

describe("detectPermissions", () => {
  it("flags a broad Bash permission rule", () => {
    const findings = detectPermissions(
      inv({
        grants: [
          {
            tool: "claude-code",
            kind: "permission-rule",
            value: "Bash(*)",
            scope: "allow",
            source: src("settings.json", "permissions.allow"),
          },
        ],
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("broad-permission");
  });

  it("does not flag a scoped Bash permission rule", () => {
    const findings = detectPermissions(
      inv({
        grants: [
          {
            tool: "claude-code",
            kind: "permission-rule",
            value: "Bash(git status:*)",
            scope: "allow",
            source: src("settings.json"),
          },
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag deny rules even when broad", () => {
    const findings = detectPermissions(
      inv({
        grants: [
          { tool: "claude-code", kind: "permission-rule", value: "Bash(*)", scope: "deny", source: src("settings.json") },
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag a broad rule for a zero-impact tool (WebSearch)", () => {
    const findings = detectPermissions(
      inv({
        grants: [
          { tool: "claude-code", kind: "permission-rule", value: "WebSearch", scope: "allow", source: src("settings.json") },
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("rates bypassPermissions mode higher than a lesser bypass value", () => {
    const [bypass] = detectPermissions(
      inv({
        grants: [{ tool: "claude-code", kind: "bypass-mode", value: "bypassPermissions", source: src("settings.json") }],
      }),
    );
    const [lesser] = detectPermissions(
      inv({
        grants: [{ tool: "claude-code", kind: "bypass-mode", value: "acceptEdits", source: src("settings.json") }],
      }),
    );
    expect(bypass?.ruleId).toBe("permission-bypass-mode");
    expect(lesser?.ruleId).toBe("permission-bypass-mode");
    const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
    expect(rank[bypass!.severity]).toBeGreaterThanOrEqual(rank[lesser!.severity]);
  });

  it("flags Codex approval_policy = never but not on-request", () => {
    const never = detectPermissions(
      inv({
        grants: [
          {
            tool: "codex",
            kind: "auto-approve",
            value: "never",
            source: src("config.toml", "approval_policy"),
          },
        ],
      }),
    );
    const onRequest = detectPermissions(
      inv({
        grants: [
          {
            tool: "codex",
            kind: "auto-approve",
            value: "on-request",
            source: src("config.toml", "approval_policy"),
          },
        ],
      }),
    );
    expect(never.some((f) => f.ruleId === "auto-approve")).toBe(true);
    expect(onRequest).toHaveLength(0);
  });

  it("flags YOLO/auto-run auto-approve values", () => {
    const findings = detectPermissions(
      inv({
        grants: [{ tool: "cursor", kind: "auto-approve", value: "yoloMode", source: src("settings.json") }],
      }),
    );
    expect(findings[0]?.ruleId).toBe("auto-approve");
    expect(findings[0]?.title).toMatch(/YOLO/i);
  });
});
