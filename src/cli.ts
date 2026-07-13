#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
/** skopecreep CLI. */
import { parseArgs } from "node:util";
import pc from "picocolors";
import { runAudit } from "./audit.js";
import { applyBaseline, type Baseline, loadBaseline, renderBaseline } from "./baseline.js";
import { type Creep, diffSnapshot, loadSnapshot, renderSnapshot } from "./diff.js";
import type { Severity, ToolId } from "./model.js";
import { renderHtml } from "./reporters/html.js";
import { renderJson } from "./reporters/json.js";
import { renderSarif } from "./reporters/sarif.js";
import { renderTerminal } from "./reporters/terminal.js";
import { scanTextForSecrets } from "./secrets/patterns.js";
import { meetsMin } from "./severity.js";
import { HOME, isDir } from "./util.js";

// Single source of truth for the version — package.json ships in every npm
// tarball, and dist/cli.js sits one level below it.
const VERSION: string = createRequire(import.meta.url)("../package.json").version;
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
  for (const part of raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)) {
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
  --format <fmt>      terminal | json | html | sarif  (default: terminal)
  --out <file>        write the report to a file instead of stdout
  --min-severity <s>  info | low | medium | high | critical  (default: low)
  --baseline <file>   suppress findings whose id is listed in this JSON file
  --write-baseline <file>  snapshot all current finding ids into a baseline file
  --write-snapshot <file>  record current posture (findings + granted surface) for --diff
  --diff <snapshot>   report creep: findings/grants/servers/hooks NEW since the snapshot
  --fail-on-new       with --diff: exit non-zero if anything new appeared
  --fail-on <s>       exit non-zero if any kept finding is >= this severity
  --verbose           also list the config files that were scanned, per tool
  --help (-h), --version (-v)
`;

function main(): void {
  // biome-ignore lint/suspicious/noImplicitAnyLet: type is inferred from the parseArgs assignment below; annotating the generic return type here would only obscure it
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
        "write-baseline": { type: "string" },
        "write-snapshot": { type: "string" },
        diff: { type: "string" },
        "fail-on-new": { type: "boolean" },
        "fail-on": { type: "string" },
        verbose: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (e) {
    // parseArgs errors carry Node-internal advice ("place it at the end of the
    // command after '--'…") that reads like a bug — keep just the diagnosis.
    const msg = (e as Error).message.split(". To specify")[0]!;
    die(`${msg}. Run skopecreep --help for usage.`);
  }
  const { values, positionals } = parsed;
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }

  const command = positionals[0] ?? "scan";
  const tools = parseTools(values.tool);
  const projectPath = path.resolve(values.path ?? process.cwd());
  if (values.path && !isDir(projectPath)) {
    die(`project path not found or not a directory: ${projectPath}`);
  }
  const generatedAt = new Date().toISOString();
  const report = runAudit({ home: HOME, projectPath, tools, generatedAt });

  if (command === "list-mcp") {
    process.stdout.write(`${renderMcpList(report.inventory.mcpServers)}\n`);
    return;
  }

  if (command === "redact-check") {
    runRedactCheck(report, generatedAt);
    return;
  }

  if (command !== "scan") die(`unknown command "${command}". See --help.`);

  const minSeverity = parseSeverity(values["min-severity"], "low");
  let baseline: Baseline;
  try {
    baseline = loadBaseline(values.baseline);
  } catch (e) {
    die((e as Error).message);
  }
  const { kept, suppressed } = applyBaseline(report.findings, baseline);
  const display = kept.filter((f) => meetsMin(f.severity, minSeverity));

  if (values["write-snapshot"]) {
    writeFileSync(values["write-snapshot"], renderSnapshot(report));
    process.stderr.write(pc.dim(`wrote posture snapshot to ${values["write-snapshot"]}\n`));
  }

  let creep: Creep | null = null;
  if (values.diff) {
    try {
      creep = diffSnapshot(report, loadSnapshot(values.diff));
    } catch (e) {
      die((e as Error).message);
    }
  }

  if (values["write-baseline"]) {
    // Snapshot everything currently found (even already-suppressed findings),
    // so the written file stands alone as the new baseline.
    writeFileSync(values["write-baseline"], renderBaseline(report.findings));
    process.stderr.write(
      pc.dim(
        `wrote baseline (${report.findings.length} finding id${report.findings.length === 1 ? "" : "s"}) to ${values["write-baseline"]}\n`,
      ),
    );
  }

  const format = (values.format ?? "terminal").toLowerCase();
  let output: string;
  const reporterArgs = {
    findings: display,
    suppressedCount: suppressed.length,
    minSeverity,
    verbose: values.verbose ?? false,
  };
  if (format === "json") {
    output = renderJson(report, reporterArgs);
  } else if (format === "terminal") {
    output = renderTerminal(report, reporterArgs);
  } else if (format === "html") {
    output = renderHtml(report, reporterArgs);
  } else if (format === "sarif") {
    output = renderSarif(report, { ...reporterArgs, projectPath });
  } else {
    die(`unknown format "${format}". Valid: terminal, json, html, sarif`);
  }

  if (values.out) {
    writeFileSync(values.out, `${output}\n`);
    process.stderr.write(
      pc.dim(`wrote ${display.length} finding${display.length === 1 ? "" : "s"} to ${values.out}\n`),
    );
  } else {
    process.stdout.write(`${output}\n`);
  }

  if (creep) {
    process.stdout.write(`${renderCreep(creep)}\n`);
    if (values["fail-on-new"] && (creep.newFindings.length > 0 || creep.newInventoryKeys.length > 0)) {
      process.exitCode = 1;
    }
  }

  const failOn = values["fail-on"] ? parseSeverity(values["fail-on"], "critical") : null;
  if (failOn && kept.some((f) => meetsMin(f.severity, failOn))) {
    process.exitCode = 1;
  }
}

function renderCreep(creep: Creep): string {
  const L: string[] = [];
  const clean = creep.newFindings.length === 0 && creep.newInventoryKeys.length === 0;
  L.push(pc.bold(`Creep since ${creep.since}`));
  if (clean) {
    L.push(pc.green("  Nothing new — posture unchanged."));
  } else {
    for (const f of creep.newFindings) {
      L.push(`  ${pc.red("+ finding")} [${f.severity}] ${f.title}`);
    }
    for (const k of creep.newInventoryKeys) {
      L.push(`  ${pc.yellow("+ granted")} ${k}`);
    }
  }
  for (const k of creep.removedInventoryKeys) {
    L.push(pc.dim(`  - removed ${k}`));
  }
  return L.join("\n");
}

function renderMcpList(
  servers: {
    tool: string;
    name: string;
    transport: string;
    command?: string;
    args?: string[];
    url?: string;
    pinned?: boolean;
    hasSecretInEnv: boolean;
  }[],
): string {
  if (servers.length === 0) return pc.dim("No MCP servers configured across scanned tools.");
  const lines = [pc.bold("MCP servers")];
  for (const s of servers.sort((a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name))) {
    const target = s.transport === "stdio" ? `${s.command ?? ""} ${(s.args ?? []).join(" ")}`.trim() : (s.url ?? "");
    const flags = [s.pinned === false ? pc.yellow("unpinned") : "", s.hasSecretInEnv ? pc.red("secret-in-env") : ""]
      .filter(Boolean)
      .join(" ");
    lines.push(`  ${pc.cyan(s.tool)}/${pc.bold(s.name)} ${pc.dim(`[${s.transport}]`)} ${target} ${flags}`.trimEnd());
  }
  return lines.join("\n");
}

function runRedactCheck(report: ReturnType<typeof runAudit>, _generatedAt: string): void {
  // Render everything at the most verbose settings and confirm no raw secret
  // signature survives into the output.
  const all = report.findings;
  const json = renderJson(report, { findings: all, suppressedCount: 0, minSeverity: "info" });
  const term = renderTerminal(report, { findings: all, suppressedCount: 0, minSeverity: "info" });
  const sarif = renderSarif(report, { findings: all, suppressedCount: 0, minSeverity: "info" });
  const combined = `${json}\n${term}\n${sarif}`;
  const leaks = scanTextForSecrets(combined);
  if (leaks.length > 0) {
    const kinds = [...new Set(leaks.map((l) => l.kind))].join(", ");
    process.stderr.write(
      pc.red(`redact-check FAILED: ${leaks.length} secret-shaped value(s) leaked into output (kinds: ${kinds})\n`),
    );
    process.exit(3);
  }
  process.stdout.write(
    pc.green(
      `redact-check OK — no secret-shaped values in rendered output (${report.findings.length} finding${report.findings.length === 1 ? "" : "s"} scanned).\n`,
    ),
  );
}

main();
