/** Collector for GitHub Copilot (~/.copilot, .github/copilot-instructions.md). */
import * as path from "node:path";
import type { Tool } from "../model.js";
import type { Collector } from "./types.js";
import { fileExists, isDir } from "../util.js";
import { makeContextSource } from "./shared.js";

const TOOL = "copilot" as const;

export const collectCopilot: Collector = (ctx, inv) => {
  const { home, projectPath } = ctx;
  const instructions = path.join(projectPath, ".github", "copilot-instructions.md");
  const installed = isDir(path.join(home, ".copilot")) || fileExists(instructions);
  const configPaths: string[] = [];
  const tool: Tool = { id: TOOL, displayName: "GitHub Copilot", installed, configPaths };
  inv.tools.push(tool);
  if (!installed) return;

  if (fileExists(instructions)) {
    configPaths.push(instructions);
    const cs = makeContextSource(TOOL, "instructions", instructions);
    if (cs) inv.contextSources.push(cs);
  }
};
