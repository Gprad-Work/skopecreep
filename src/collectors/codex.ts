/** Collector for OpenAI Codex CLI (~/.codex). */
import * as path from "node:path";
import { parse as parseToml } from "smol-toml";
import type { Inventory, Tool } from "../model.js";
import type { Collector } from "./types.js";
import { fileExists, isDir, readTextSafe } from "../util.js";
import { parseMcpMap } from "./mcpShared.js";
import { collectCredentialFromFile, makeContextSource } from "./shared.js";

const TOOL = "codex" as const;

/** Parse Codex `prefix_rule(pattern=[...], decision="allow")` blocks into allow prefixes. */
export function parseCodexRules(text: string): string[] {
  const prefixes: string[] = [];
  const blocks = text.match(/prefix_rule\s*\([\s\S]*?\)/g) ?? [];
  for (const b of blocks) {
    const dec = /decision\s*=\s*["']([^"']+)["']/.exec(b)?.[1] ?? "allow";
    if (dec.toLowerCase() !== "allow") continue;
    const patMatch = /pattern\s*=\s*\[([\s\S]*?)\]/.exec(b);
    if (!patMatch) continue;
    const strs = patMatch[1]!.match(/["']([^"']+)["']/g) ?? [];
    for (const s of strs) prefixes.push(s.slice(1, -1));
  }
  return prefixes;
}

export const collectCodex: Collector = (ctx, inv) => {
  const { home } = ctx;
  const codexDir = path.join(home, ".codex");
  const installed = isDir(codexDir);
  const configPaths: string[] = [];
  const tool: Tool = { id: TOOL, displayName: "OpenAI Codex CLI", installed, configPaths };
  inv.tools.push(tool);
  if (!installed) return;

  // config.toml
  const configPath = path.join(codexDir, "config.toml");
  const cfgText = readTextSafe(configPath);
  if (cfgText !== null) {
    configPaths.push(configPath);
    let cfg: Record<string, any> | null = null;
    try {
      cfg = parseToml(cfgText) as Record<string, any>;
    } catch (e) {
      inv.errors.push({ tool: TOOL, path: configPath, message: `TOML parse failed: ${(e as Error).message}` });
    }
    if (cfg) {
      const servers = cfg.mcp_servers as Record<string, any> | undefined;
      inv.mcpServers.push(...parseMcpMap(TOOL, servers, configPath));
      // Per-server auto-approval mode.
      if (servers && typeof servers === "object") {
        for (const [name, entry] of Object.entries(servers)) {
          const mode = (entry as Record<string, unknown>)?.default_tools_approval_mode;
          if (typeof mode === "string" && !["prompt", "on-request", "on_request"].includes(mode.toLowerCase())) {
            inv.grants.push({
              tool: TOOL,
              kind: "auto-approve",
              value: `${name}: ${mode}`,
              source: { path: configPath, locator: `mcp_servers.${name}.default_tools_approval_mode` },
            });
          }
        }
      }

      const projects = cfg.projects as Record<string, any> | undefined;
      if (projects && typeof projects === "object") {
        for (const [projPath, pconf] of Object.entries(projects)) {
          const trust = (pconf as Record<string, unknown>)?.trust_level;
          if (typeof trust === "string") {
            inv.grants.push({
              tool: TOOL,
              kind: "trusted-dir",
              value: trust,
              scope: projPath,
              source: { path: configPath, locator: `projects."${projPath}".trust_level` },
            });
          }
        }
      }

      if (typeof cfg.approval_policy === "string") {
        inv.grants.push({ tool: TOOL, kind: "auto-approve", value: cfg.approval_policy, source: { path: configPath, locator: "approval_policy" } });
      }
      if (typeof cfg.sandbox_mode === "string") {
        inv.grants.push({ tool: TOOL, kind: "sandbox", value: cfg.sandbox_mode, source: { path: configPath, locator: "sandbox_mode" } });
      }

      const plugins = cfg.plugins as Record<string, any> | undefined;
      if (plugins && typeof plugins === "object") {
        for (const [name, pconf] of Object.entries(plugins)) {
          if ((pconf as Record<string, unknown>)?.enabled === true) {
            inv.capabilityDefs.push({ tool: TOOL, kind: "plugin", name, grantedTools: [], source: { path: configPath, locator: `plugins.${name}` } });
          }
        }
      }
    }
  }

  // auth.json — plaintext OAuth tokens.
  const authPath = path.join(codexDir, "auth.json");
  if (fileExists(authPath)) {
    configPaths.push(authPath);
    const cred = collectCredentialFromFile(TOOL, authPath);
    if (cred) inv.credentials.push(cred);
  }

  // AGENTS.md instructions.
  const agentsMd = path.join(codexDir, "AGENTS.md");
  if (fileExists(agentsMd)) {
    const cs = makeContextSource(TOOL, "instructions", agentsMd);
    if (cs) inv.contextSources.push(cs);
  }

  // rules/default.rules command allowlist.
  const rulesPath = path.join(codexDir, "rules", "default.rules");
  const rulesText = readTextSafe(rulesPath);
  if (rulesText !== null) {
    configPaths.push(rulesPath);
    for (const prefix of parseCodexRules(rulesText)) {
      inv.grants.push({ tool: TOOL, kind: "allowlist-cmd", value: prefix, source: { path: rulesPath } });
    }
  }
};
