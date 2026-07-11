/** Over-broad permission grants, permission-bypass modes, and auto-approval. */
import type { Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity, type Dim } from "../severity.js";
import { makeFindingId } from "./util.js";

/** How powerful is the tool a permission rule grants? */
function impactForTool(tool: string): Dim {
  const t = tool.toLowerCase();
  if (["bash", "shell", "terminal", "run"].includes(t)) return 3;
  if (["write", "edit", "multiedit", "notebookedit"].includes(t)) return 2;
  if (["webfetch", "fetch"].includes(t)) return 2;
  if (["read"].includes(t)) return 1;
  return 0; // e.g. WebSearch, harmless — don't flag
}

interface ParsedRule {
  tool: string;
  broad: boolean;
}

function parseRule(value: string): ParsedRule | null {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\((.*)\))?$/.exec(value.trim());
  if (!m) return null;
  const tool = m[1]!;
  const arg = (m[2] ?? "").trim();
  const broad =
    arg === "" || arg === "*" || arg === ":*" || arg === "*:*" || /^\*[:*]?$/.test(arg);
  return { tool, broad };
}

export const detectPermissions: Detector = (inv) => {
  const findings: Finding[] = [];

  for (const g of inv.grants) {
    if (g.kind === "permission-rule") {
      if (g.scope === "deny") continue; // deny rules are protective
      const parsed = parseRule(g.value);
      if (!parsed || !parsed.broad) continue;
      const impact = impactForTool(parsed.tool);
      if (impact === 0) continue;
      findings.push({
        id: makeFindingId("broad-permission", [g.tool, g.source.path, g.value]),
        ruleId: "broad-permission",
        tool: g.tool,
        severity: computeSeverity({ impact, exposure: 2, exploitability: 2 }),
        confidence: "high",
        title: `Broad auto-allow permission: ${g.value}`,
        rationale:
          `An "${g.scope}" rule "${g.value}" grants the ${parsed.tool} capability with no scoping (${g.source.path}). ` +
          `A prompt-injection or a mistaken step can then use it without a confirmation gate.`,
        remediation: {
          loose: `Scope the rule to the specific commands/paths you actually repeat (e.g. Bash(git status:*) instead of Bash(*)).`,
          medium: `Move the broad rule to "ask" so the capability stays one keypress away but never fires unseen.`,
          tight: `Delete the rule and approve per use; add narrow allow rules only after a command has proven routine and side-effect-free.`,
        },
        evidence: [{ path: g.source.path, locator: g.source.locator, redactedSnippet: `${g.scope}: ${g.value}` }],
      });
    } else if (g.kind === "bypass-mode") {
      const bypass = g.value === "bypassPermissions";
      findings.push({
        id: makeFindingId("permission-bypass-mode", [g.tool, g.source.path, g.value]),
        ruleId: "permission-bypass-mode",
        tool: g.tool,
        severity: computeSeverity({ impact: bypass ? 3 : 2, exposure: 2, exploitability: 2 }),
        confidence: "high",
        title: `Default mode "${g.value}" reduces confirmation prompts`,
        rationale:
          `A saved default mode of "${g.value}" (${g.source.path}) means sessions start with reduced or no permission gating, ` +
          `so tool calls (including ones triggered by injected content) run with fewer checks.`,
        remediation: {
          loose: `Keep the mode but confine it to a single trusted, sandboxed project instead of a global default.`,
          medium: `Remove the saved default; opt into the reduced-prompting mode per session when a task genuinely needs it.`,
          tight: `Remove it and run high-autonomy sessions only inside a container/VM where a bad tool call can't reach your real files or credentials.`,
        },
        evidence: [{ path: g.source.path, locator: g.source.locator, redactedSnippet: g.value }],
      });
    } else if (g.kind === "auto-approve") {
      const v = g.value.toLowerCase();
      const loc = (g.source.locator ?? "").toLowerCase();
      let sev: { impact: Dim; exposure: Dim; exploitability: Dim } | null = null;
      let title = `Auto-approval enabled: ${g.value}`;
      if (v.includes("yolo") || v.includes("autorun") || v.includes("auto_run") || v.includes("autoexecute")) {
        sev = { impact: 3, exposure: 2, exploitability: 2 };
        title = `Auto-run / YOLO mode enabled (${g.value})`;
      } else if (loc === "approval_policy") {
        if (!v.includes("never")) continue; // on-failure/on-request are fine
        sev = { impact: 3, exposure: 2, exploitability: 2 };
        title = `Codex approval_policy = "${g.value}" (never prompts)`;
      } else if (loc.includes("default_tools_approval_mode")) {
        sev = { impact: 2, exposure: 2, exploitability: 2 };
        title = `MCP tools auto-approved (${g.value})`;
      } else if (v === "enableallprojectmcpservers") {
        sev = { impact: 2, exposure: 1, exploitability: 1 };
        title = `All project MCP servers auto-enabled`;
      } else {
        sev = { impact: 2, exposure: 2, exploitability: 1 };
      }
      findings.push({
        id: makeFindingId("auto-approve", [g.tool, g.source.path, g.value]),
        ruleId: "auto-approve",
        tool: g.tool,
        severity: computeSeverity(sev),
        confidence: "medium",
        title,
        rationale:
          `${g.source.path} enables automatic approval ("${g.value}"), so the agent can invoke tools/servers without a per-use prompt. ` +
          `This removes a key defense against injected or erroneous actions.`,
        remediation: {
          loose: `Carve out the dangerous categories: keep auto-approval for read-only tools but require prompts for shell, network, and file writes.`,
          medium: `Turn the auto-approval off and approve per use; most workflows lose very little speed.`,
          tight: `Turn it off and pair per-use approval with a sandboxed working directory, so even an approved mistake stays contained.`,
        },
        evidence: [{ path: g.source.path, locator: g.source.locator, redactedSnippet: g.value }],
      });
    }
  }

  return findings;
};
