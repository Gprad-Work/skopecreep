import { describe, it, expect } from "vitest";
import { computeSeverity, riskScore } from "../dist/severity.js";

describe("calibrated severity", () => {
  it("rates a 600-perm secret in $HOME as medium, not high", () => {
    // impact 3 (account token), exposure 1 (owner-only), exploit 1 (needs local access)
    expect(computeSeverity({ impact: 3, exposure: 1, exploitability: 1 })).toBe("medium");
  });

  it("escalates the same secret to high when world-readable", () => {
    expect(computeSeverity({ impact: 3, exposure: 3, exploitability: 1 })).toBe("high");
  });

  it("escalates to critical in a VCS/synced dir with easy trigger", () => {
    expect(computeSeverity({ impact: 3, exposure: 3, exploitability: 2 })).toBe("critical");
  });

  it("NEVER escalates a zero-impact observation (the cloudId false-positive class)", () => {
    expect(computeSeverity({ impact: 0, exposure: 3, exploitability: 3 })).toBe("info");
    expect(riskScore({ impact: 0, exposure: 3, exploitability: 3 })).toBe(0);
  });

  it("rates an unpinned MCP package (impact 3, exposure 2, exploit 1) as medium", () => {
    expect(computeSeverity({ impact: 3, exposure: 2, exploitability: 1 })).toBe("medium");
  });

  it("rates a broad trusted parent dir (impact 2, exposure 2, exploit 1) as medium", () => {
    expect(computeSeverity({ impact: 2, exposure: 2, exploitability: 1 })).toBe("medium");
  });
});
