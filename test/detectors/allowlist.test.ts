import { describe, it, expect } from "vitest";
import { detectAllowlist } from "../../dist/detectors/allowlist.js";
import { inv, src } from "./helpers.js";

describe("detectAllowlist", () => {
  it("flags an unconstrained HIGH-tier binary (bash) as high severity", () => {
    const findings = detectAllowlist(
      inv({
        grants: [{ tool: "codex", kind: "allowlist-cmd", value: "bash", source: src("rules/default.rules") }],
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("broad-cmd-allowlist");
    expect(findings[0]?.severity).toBe("high");
  });

  it("flags an unconstrained MED-tier binary (curl) at a lower severity than bash", () => {
    const findings = detectAllowlist(
      inv({
        grants: [{ tool: "codex", kind: "allowlist-cmd", value: "curl", source: src("rules/default.rules") }],
      }),
    );
    expect(findings[0]?.severity).toBe("medium");
  });

  it("pulls severity down for a fully-constrained command (fixed URL)", () => {
    const unconstrained = detectAllowlist(
      inv({ grants: [{ tool: "codex", kind: "allowlist-cmd", value: "curl", source: src("rules.txt") }] }),
    );
    const constrained = detectAllowlist(
      inv({
        grants: [
          { tool: "codex", kind: "allowlist-cmd", value: "curl https://api.example.com/v1/data", source: src("rules.txt") },
        ],
      }),
    );
    const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
    expect(rank[constrained[0]!.severity]).toBeLessThan(rank[unconstrained[0]!.severity]);
  });

  it("does not flag a binary outside the risky sets (ls)", () => {
    const findings = detectAllowlist(
      inv({ grants: [{ tool: "codex", kind: "allowlist-cmd", value: "ls", source: src("rules.txt") }] }),
    );
    expect(findings).toHaveLength(0);
  });

  it("groups multiple risky prefixes from the same source file into one finding", () => {
    const findings = detectAllowlist(
      inv({
        grants: [
          { tool: "codex", kind: "allowlist-cmd", value: "bash", source: src("rules.txt") },
          { tool: "codex", kind: "allowlist-cmd", value: "curl", source: src("rules.txt") },
        ],
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toMatch(/^2 shell command/);
  });

  it("keeps risky prefixes from different source files as separate findings", () => {
    const findings = detectAllowlist(
      inv({
        grants: [
          { tool: "codex", kind: "allowlist-cmd", value: "bash", source: src("a.rules") },
          { tool: "codex", kind: "allowlist-cmd", value: "bash", source: src("b.rules") },
        ],
      }),
    );
    expect(findings).toHaveLength(2);
  });
});
