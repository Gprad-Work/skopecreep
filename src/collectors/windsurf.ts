/** Collector for Windsurf / Codeium (~/.codeium/windsurf). */
import * as path from "node:path";
import type { Tool } from "../model.js";
import { fileExists, isDir, parseJsoncSafe, readTextSafe } from "../util.js";
import { parseMcpMap } from "./mcpShared.js";
import { makeContextSource } from "./shared.js";
import type { Collector } from "./types.js";

const TOOL = "windsurf" as const;

export const collectWindsurf: Collector = (ctx, inv) => {
  const { home, projectPath } = ctx;
  const codeiumDir = path.join(home, ".codeium");
  const installed = isDir(codeiumDir);
  const configPaths: string[] = [];
  const tool: Tool = { id: TOOL, displayName: "Windsurf / Codeium", installed, configPaths };
  inv.tools.push(tool);
  if (!installed) return;

  const mcpPath = path.join(codeiumDir, "windsurf", "mcp_config.json");
  const text = readTextSafe(mcpPath);
  if (text !== null) {
    configPaths.push(mcpPath);
    const json = parseJsoncSafe<any>(text);
    inv.mcpServers.push(...parseMcpMap(TOOL, json?.mcpServers ?? json, mcpPath));
  }

  const rules = path.join(projectPath, ".windsurfrules");
  if (fileExists(rules)) {
    const cs = makeContextSource(TOOL, "rule", rules);
    if (cs) inv.contextSources.push(cs);
  }
};
