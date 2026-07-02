#!/usr/bin/env node
/** skopecreep CLI. */
import { parseArgs } from "node:util";
import { writeFileSync } from "node:fs";
import * as path from "node:path";
import pc from "picocolors";
import { ALL_TOOL_IDS, type Severity, type ToolId } from "./model.js";
import { HOME } from "./util.js";
import { runAudit } from "./audit.js";
import { applyBaseline, loadBaseline } from "./baseline.js";
import { meetsMin, severityRank } from "./severity.js";
import { renderTerminal } from "./reporters/terminal.js";
import { renderJson } from "./reporters/json.js";
import { renderHtml } from "./reporters/html.js";
import { scanTextForSecrets } from "./secrets/patterns.js";

const VERSION = "0.1.0";
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

const TOOL_ALIASES: Record<string, ToolId> = {
  claude: "claude-code",
  "claude-code": "claude-code",
  claudecode: "claude-code",
  codex: "codex",
  cursor: "cursor",
  windsurf: "windsurf",
  codeium: "windsurf",
  copilot: "copilot",
  generic: "generic",
};

function parseTools(raw: string | undefined): ToolId[] | undefined {
  if (!raw) return undefined;
  const out: ToolId[] = [];
  for (const part of raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)) {
    const id = TOOL_ALIASES[part];
    if (!id) die(`unknown tool "${part}". Valid: ${Object.keys(TOOL_ALIASES).join(", ")}`);
    if (!out.includes(id)) out.push(id);
  }
  return out.length ? out : undefined;
}

function parseSeverity(raw: string | undefined, fallback: Severity): Severity {
  if (!raw) return fallback;
  const s = raw.trim().toLowerCase();
  if (!SEVERITIES.includes(s as Severity)) die(`invalid severity "${raw}". Valid: ${SEVERITIES.join(", ")}`);
  return s as Severity;
}

function die(msg: string): never {
  process.stderr.write(pc.red(`error: ${msg}\n`));
  process.exit(2);
}

const USAGE = `${pc.bold("skopecreep")} — audit the scope your AI coding tools have been granted

${pc.bold("Usage")}
  skopecreep [scan] [options]      audit config & granted scope (default)
  skopecreep list-mcp [options]    list configured MCP servers across tools
  skopecreep redact-check          self-test: assert no secret leaks into output

${pc.bold("Options")}
  --tool <a,b>        limit to tools: claude, codex, cursor, windsurf, copilot, generic
  --path <dir>        project dir to scan for project-scoped config (default: cwd)
  --format <fmt>      terminal | json | html  (default: terminal)
  --out <file>        write the report to a file instead of stdout
  --min-severity <s>  info | low | medium | high | critical  (default: low)
  --baseline <file>   suppress findings whose id is listed in this JSON file
  --fail-on <s>       exit non-zero if any kept finding is >= this severity
  --help, --version
`;

function main(): void {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        tool: { type: "string" },
        path: { type: "string" },
        format: { type: "string" },
        out: { type: "string" },
        "min-severity": { type: "string" },
        baseline: { type: "string" },
        "fail-on": { type: "string" },
        help: { type: "boolean" },
        version: { type: "boolean" },
      },
    });
  } catch (e) {
    die((e as Error).message);
  }
  const { values, positionals } = parsed;
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (values.help) {
    process.stdout.write(USAGE + "\n");
    return;
  }

  const command = positionals[0] ?? "scan";
  const tools = parseTools(values.tool);
  const projectPath = path.resolve(values.path ?? process.cwd());
  const generatedAt = new Date().toISOString();
  const report = runAudit({ home: HOME, projectPath, tools, generatedAt });

  if (command === "list-mcp") {
    process.stdout.write(renderMcpList(report.inventory.mcpServers) + "\n");
    return;
  }

  if (command === "redact-check") {
    runRedactCheck(report, generatedAt);
    return;
  }

  if (command !== "scan") die(`unknown command "${command}". See --help.`);

  const minSeverity = parseSeverity(values["min-severity"], "low");
  const baseline = loadBaseline(values.baseline);
  const { kept, suppressed } = applyBaseline(report.findings, baseline);
  const display = kept.filter((f) => meetsMin(f.severity, minSeverity));

  const format = (values.format ?? "terminal").toLowerCase();
  let output: string;
  const reporterArgs = { findings: display, suppressedCount: suppressed.length, minSeverity };
  if (format === "json") {
    output = renderJson(report, reporterArgs);
  } else if (format === "terminal") {
    output = renderTerminal(report, reporterArgs);
  } else if (format === "html") {
    output = renderHtml(report, reporterArgs);
  } else {
    die(`unknown format "${format}". Valid: terminal, json, html`);
  }

  if (values.out) {
    writeFileSync(values.out, output + "\n");
    process.stderr.write(pc.dim(`wrote ${display.length} finding(s) to ${values.out}\n`));
  } else {
    process.stdout.write(output + "\n");
  }

  const failOn = values["fail-on"] ? parseSeverity(values["fail-on"], "critical") : null;
  if (failOn && kept.some((f) => meetsMin(f.severity, failOn))) {
    process.exitCode = 1;
  }
}

function renderMcpList(servers: { tool: string; name: string; transport: string; command?: string; args?: string[]; url?: string; pinned?: boolean; hasSecretInEnv: boolean }[]): string {
  if (servers.length === 0) return pc.dim("No MCP servers configured across scanned tools.");
  const lines = [pc.bold("MCP servers")];
  for (const s of servers.sort((a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name))) {
    const target = s.transport === "stdio" ? `${s.command ?? ""} ${(s.args ?? []).join(" ")}`.trim() : s.url ?? "";
    const flags = [
      s.pinned === false ? pc.yellow("unpinned") : "",
      s.hasSecretInEnv ? pc.red("secret-in-env") : "",
    ].filter(Boolean).join(" ");
    lines.push(`  ${pc.cyan(s.tool)}/${pc.bold(s.name)} ${pc.dim(`[${s.transport}]`)} ${target} ${flags}`.trimEnd());
  }
  return lines.join("\n");
}

function runRedactCheck(report: ReturnType<typeof runAudit>, generatedAt: string): void {
  // Render everything at the most verbose settings and confirm no raw secret
  // signature survives into the output.
  const all = report.findings;
  const json = renderJson(report, { findings: all, suppressedCount: 0, minSeverity: "info" });
  const term = renderTerminal(report, { findings: all, suppressedCount: 0, minSeverity: "info" });
  const combined = json + "\n" + term;
  const leaks = scanTextForSecrets(combined);
  if (leaks.length > 0) {
    const kinds = [...new Set(leaks.map((l) => l.kind))].join(", ");
    process.stderr.write(pc.red(`redact-check FAILED: ${leaks.length} secret-shaped value(s) leaked into output (kinds: ${kinds})\n`));
    process.exit(3);
  }
  process.stdout.write(pc.green(`redact-check OK — no secret-shaped values in rendered output (${report.findings.length} findings scanned).\n`));
}

main();
