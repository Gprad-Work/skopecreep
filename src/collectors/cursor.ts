/** Collector for Cursor (~/.cursor, project .cursor/, VSCode-style settings). */
import * as path from "node:path";
import type { Inventory, Tool } from "../model.js";
import { fileExists, isDir, listDir, parseJsoncSafe, readTextSafe } from "../util.js";
import { parseMcpMap } from "./mcpShared.js";
import { makeContextSource } from "./shared.js";
import type { Collector } from "./types.js";

const TOOL = "cursor" as const;

function getMcpMap(json: any): Record<string, any> | undefined {
  if (!json || typeof json !== "object") return undefined;
  if (json.mcpServers && typeof json.mcpServers === "object") return json.mcpServers;
  return json; // some files are the bare map
}

const AUTO_RUN_KEY = /yolo|autorun|auto_run|autoapprove|auto_execute|autoexecute/i;

function scanAutoRun(obj: unknown, source: string, inv: Inventory, prefix = "", depth = 0): void {
  if (depth > 6 || !obj || typeof obj !== "object") return;
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const keyPath = prefix ? `${prefix}.${k}` : k;
    if (v === true && AUTO_RUN_KEY.test(k)) {
      inv.grants.push({ tool: TOOL, kind: "auto-approve", value: keyPath, source: { path: source, locator: keyPath } });
    } else if (v && typeof v === "object") {
      scanAutoRun(v, source, inv, keyPath, depth + 1);
    }
  }
}

export const collectCursor: Collector = (ctx, inv) => {
  const { home, projectPath } = ctx;
  const cursorDir = path.join(home, ".cursor");
  const installed = isDir(cursorDir);
  const configPaths: string[] = [];
  const tool: Tool = { id: TOOL, displayName: "Cursor", installed, configPaths };
  inv.tools.push(tool);
  if (!installed) return;

  const mcpFiles = [path.join(cursorDir, "mcp.json"), path.join(projectPath, ".cursor", "mcp.json")];
  for (const f of mcpFiles) {
    const text = readTextSafe(f);
    if (text === null) continue;
    configPaths.push(f);
    inv.mcpServers.push(...parseMcpMap(TOOL, getMcpMap(parseJsoncSafe(text)), f));
  }

  // VSCode-style user settings (macOS path).
  const settingsPath = path.join(home, "Library", "Application Support", "Cursor", "User", "settings.json");
  const settingsText = readTextSafe(settingsPath);
  if (settingsText !== null) {
    configPaths.push(settingsPath);
    scanAutoRun(parseJsoncSafe(settingsText), settingsPath, inv);
  }

  // Rules.
  for (const f of [path.join(projectPath, ".cursorrules"), path.join(home, ".cursorrules")]) {
    if (!fileExists(f)) continue;
    const cs = makeContextSource(TOOL, "rule", f);
    if (cs) inv.contextSources.push(cs);
  }
  const rulesDir = path.join(projectPath, ".cursor", "rules");
  if (isDir(rulesDir)) {
    for (const f of listDir(rulesDir)) {
      if (!f.endsWith(".mdc") && !f.endsWith(".md")) continue;
      const cs = makeContextSource(TOOL, "rule", path.join(rulesDir, f));
      if (cs) inv.contextSources.push(cs);
    }
  }
};
