/** Collector registry — runs the selected tool collectors into one Inventory. */
import { ALL_TOOL_IDS, emptyInventory, type Inventory, type ToolId } from "../model.js";
import type { Collector, CollectorContext } from "./types.js";
import { collectClaudeCode } from "./claudeCode.js";
import { collectCodex } from "./codex.js";
import { collectCursor } from "./cursor.js";
import { collectWindsurf } from "./windsurf.js";
import { collectCopilot } from "./copilot.js";
import { collectGeneric } from "./generic.js";

export const COLLECTORS: Record<ToolId, Collector> = {
  "claude-code": collectClaudeCode,
  codex: collectCodex,
  cursor: collectCursor,
  windsurf: collectWindsurf,
  copilot: collectCopilot,
  generic: collectGeneric,
};

export function collectAll(ctx: CollectorContext, tools?: ToolId[]): Inventory {
  const inv = emptyInventory();
  for (const id of tools ?? ALL_TOOL_IDS) {
    try {
      COLLECTORS[id](ctx, inv);
    } catch (e) {
      inv.errors.push({ tool: id, message: `collector failed: ${(e as Error).message}` });
    }
  }
  return inv;
}

export type { CollectorContext } from "./types.js";
