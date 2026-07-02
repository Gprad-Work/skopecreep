/** Cross-tool catch-all: AGENTS.md and .mcp.json anywhere in the project tree. */
import * as path from "node:path";
import type { Tool } from "../model.js";
import type { Collector } from "./types.js";
import { fileExists, parseJsoncSafe, readTextSafe, walk } from "../util.js";
import { parseMcpMap } from "./mcpShared.js";
import { makeContextSource } from "./shared.js";

const TOOL = "generic" as const;

const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  "out",
  "coverage",
  "target",
  "vendor",
  ".venv",
  "venv",
  ".next",
  ".turbo",
  ".cache",
]);

export const collectGeneric: Collector = (ctx, inv) => {
  const { home, projectPath } = ctx;
  const tool: Tool = { id: TOOL, displayName: "Generic (AGENTS.md / .mcp.json)", installed: true, configPaths: [] };
  inv.tools.push(tool);

  const found = walk(projectPath, {
    maxDepth: 4,
    skipDirs: SKIP_DIRS,
    match: (b) => b === "AGENTS.md" || b === ".mcp.json",
  });
  // Also a home-level AGENTS.md (a common global convention).
  const homeAgents = path.join(home, "AGENTS.md");
  if (fileExists(homeAgents)) found.push(homeAgents);

  for (const f of found) {
    tool.configPaths.push(f);
    if (path.basename(f) === "AGENTS.md") {
      const cs = makeContextSource(TOOL, "instructions", f);
      if (cs) inv.contextSources.push(cs);
    } else {
      const text = readTextSafe(f);
      if (text === null) continue;
      const json = parseJsoncSafe<any>(text);
      inv.mcpServers.push(...parseMcpMap(TOOL, json?.mcpServers ?? json, f));
    }
  }
};
