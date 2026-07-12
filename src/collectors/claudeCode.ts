/** Collector for Claude Code (~/.claude, ~/.claude.json, project .claude/). */
import * as path from "node:path";
import { parse as parseYaml } from "yaml";
import type { Inventory, Tool } from "../model.js";
import { fileExists, isDir, listDir, parseJsoncSafe, parseJsonSafe, readTextSafe } from "../util.js";
import { parseMcpMap } from "./mcpShared.js";
import { collectCredentialFromFile, makeContextSource } from "./shared.js";
import type { Collector } from "./types.js";

const TOOL = "claude-code" as const;

function extractFrontmatter(text: string): string | null {
  if (!text.startsWith("---")) return null;
  const end = text.indexOf("\n---", 3);
  if (end === -1) return null;
  return text.slice(text.indexOf("\n") + 1, end);
}

function parseGrantedTools(text: string): { name?: string; tools: string[] } {
  const fm = extractFrontmatter(text);
  if (!fm) return { tools: [] };
  let data: Record<string, unknown> | null = null;
  try {
    data = parseYaml(fm) as Record<string, unknown>;
  } catch {
    return { tools: [] };
  }
  const name = typeof data?.name === "string" ? data.name : undefined;
  let tools = data?.tools as unknown;
  if (typeof tools === "string") {
    tools = tools
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return { name, tools: Array.isArray(tools) ? (tools as string[]) : [] };
}

/** Pull permissions, hooks and mode out of a settings object. */
function processSettings(settings: Record<string, unknown> | null, sourcePath: string, inv: Inventory): void {
  if (!settings) return;
  const perms = settings.permissions as Record<string, unknown> | undefined;
  const buckets: Array<"allow" | "ask" | "deny"> = ["allow", "ask", "deny"];
  for (const bucket of buckets) {
    const rules = perms?.[bucket];
    if (Array.isArray(rules)) {
      for (const r of rules) {
        if (typeof r !== "string") continue;
        inv.grants.push({
          tool: TOOL,
          kind: "permission-rule",
          value: r,
          scope: bucket,
          source: { path: sourcePath, locator: `permissions.${bucket}` },
        });
      }
    }
  }

  const mode = (perms?.defaultMode as string | undefined) ?? (settings.defaultMode as string | undefined);
  if (mode === "bypassPermissions" || mode === "acceptEdits") {
    inv.grants.push({
      tool: TOOL,
      kind: "bypass-mode",
      value: mode,
      source: { path: sourcePath, locator: "defaultMode" },
    });
  }
  if (settings.enableAllProjectMcpServers === true) {
    inv.grants.push({
      tool: TOOL,
      kind: "auto-approve",
      value: "enableAllProjectMcpServers",
      source: { path: sourcePath, locator: "enableAllProjectMcpServers" },
    });
  }

  const hooks = settings.hooks as Record<string, unknown> | undefined;
  if (hooks && typeof hooks === "object") {
    for (const [event, groups] of Object.entries(hooks)) {
      if (!Array.isArray(groups)) continue;
      for (const g of groups) {
        const list = (g as Record<string, unknown>)?.hooks;
        if (!Array.isArray(list)) continue;
        for (const h of list) {
          const cmd = (h as Record<string, unknown>)?.command;
          if (typeof cmd === "string") {
            inv.hooks.push({
              tool: TOOL,
              event,
              command: cmd,
              source: { path: sourcePath, locator: `hooks.${event}` },
            });
          }
        }
      }
    }
  }
}

function collectAgents(dir: string, inv: Inventory): void {
  if (!isDir(dir)) return;
  for (const f of listDir(dir)) {
    if (!f.endsWith(".md")) continue;
    const full = path.join(dir, f);
    const text = readTextSafe(full);
    if (text === null) continue;
    const { name, tools } = parseGrantedTools(text);
    inv.capabilityDefs.push({
      tool: TOOL,
      kind: "agent",
      name: name ?? f.replace(/\.md$/, ""),
      grantedTools: tools,
      source: { path: full },
    });
    const cs = makeContextSource(TOOL, "agent", full);
    if (cs) inv.contextSources.push(cs);
  }
}

function collectMemory(home: string, inv: Inventory): void {
  const projectsDir = path.join(home, ".claude", "projects");
  if (!isDir(projectsDir)) return;
  for (const slug of listDir(projectsDir)) {
    const memDir = path.join(projectsDir, slug, "memory");
    if (!isDir(memDir)) continue;
    for (const f of listDir(memDir)) {
      if (!f.endsWith(".md")) continue;
      const cs = makeContextSource(TOOL, "memory", path.join(memDir, f));
      if (cs) inv.contextSources.push(cs);
    }
  }
}

export const collectClaudeCode: Collector = (ctx, inv) => {
  const { home, projectPath } = ctx;
  const claudeDir = path.join(home, ".claude");
  const globalJson = path.join(home, ".claude.json");
  const installed = isDir(claudeDir) || fileExists(globalJson);

  const configPaths: string[] = [];
  const tool: Tool = { id: TOOL, displayName: "Claude Code", installed, configPaths };
  inv.tools.push(tool);
  if (!installed) return;

  // ~/.claude.json — global + per-project MCP servers and allowedTools.
  const bigText = readTextSafe(globalJson);
  if (bigText !== null) {
    configPaths.push(globalJson);
    const big = parseJsonSafe<Record<string, any>>(bigText);
    if (big) {
      inv.mcpServers.push(...parseMcpMap(TOOL, big.mcpServers, globalJson));
      const projects = big.projects as Record<string, any> | undefined;
      if (projects && typeof projects === "object") {
        for (const [projPath, pconf] of Object.entries(projects)) {
          inv.mcpServers.push(...parseMcpMap(TOOL, pconf?.mcpServers, globalJson));
          const allowed = pconf?.allowedTools;
          if (Array.isArray(allowed)) {
            for (const t of allowed) {
              if (typeof t !== "string") continue;
              inv.grants.push({
                tool: TOOL,
                kind: "permission-rule",
                value: t,
                scope: "allow",
                source: { path: globalJson, locator: `projects.${projPath}.allowedTools` },
              });
            }
          }
        }
      }
    }
  }

  // claude.ai-hosted (managed OAuth) MCP connectors are tracked here rather
  // than in `mcpServers`. Inventory them so the MCP picture is complete.
  const authCachePath = path.join(claudeDir, "mcp-needs-auth-cache.json");
  const authCacheText = readTextSafe(authCachePath);
  if (authCacheText !== null) {
    configPaths.push(authCachePath);
    const cache = parseJsonSafe<Record<string, unknown>>(authCacheText);
    if (cache && typeof cache === "object") {
      for (const name of Object.keys(cache)) {
        inv.mcpServers.push({
          tool: TOOL,
          name,
          transport: "http",
          host: "claude.ai",
          url: "claude.ai (managed connector)",
          envKeys: [],
          secretEnvKeys: [],
          hasSecretInEnv: false,
          source: { path: authCachePath, locator: name },
        });
      }
    }
  }

  // ~/.claude/.credentials.json — plaintext OAuth tokens on hosts where no
  // OS keychain is available (Linux/headless).
  const credPath = path.join(claudeDir, ".credentials.json");
  if (fileExists(credPath)) {
    configPaths.push(credPath);
    const cred = collectCredentialFromFile(TOOL, credPath);
    if (cred) inv.credentials.push(cred);
  }

  // Settings files (global + project).
  const settingsFiles = [
    path.join(claudeDir, "settings.json"),
    path.join(claudeDir, "settings.local.json"),
    path.join(projectPath, ".claude", "settings.json"),
    path.join(projectPath, ".claude", "settings.local.json"),
  ];
  for (const sf of settingsFiles) {
    const text = readTextSafe(sf);
    if (text === null) continue;
    configPaths.push(sf);
    processSettings(parseJsoncSafe<Record<string, unknown>>(text), sf, inv);
  }

  // Instruction / rule context.
  const instructionFiles = [
    path.join(claudeDir, "CLAUDE.md"),
    path.join(projectPath, "CLAUDE.md"),
    path.join(projectPath, ".claude", "CLAUDE.md"),
  ];
  for (const f of instructionFiles) {
    if (!fileExists(f)) continue;
    const cs = makeContextSource(TOOL, "instructions", f);
    if (cs) inv.contextSources.push(cs);
  }
  const rulesDir = path.join(projectPath, ".claude", "rules");
  if (isDir(rulesDir)) {
    for (const f of listDir(rulesDir)) {
      if (!f.endsWith(".md")) continue;
      const cs = makeContextSource(TOOL, "rule", path.join(rulesDir, f));
      if (cs) inv.contextSources.push(cs);
    }
  }

  collectAgents(path.join(claudeDir, "agents"), inv);
  collectAgents(path.join(projectPath, ".claude", "agents"), inv);
  collectMemory(home, inv);
};
