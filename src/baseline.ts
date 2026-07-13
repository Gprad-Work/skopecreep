/** Baseline suppression: accept known findings so repeat runs stay quiet. */
import type { Finding } from "./model.js";
import { parseJsonSafe, readTextSafe } from "./util.js";

export interface Baseline {
  ignore: Set<string>;
}

/**
 * Accepts either `["id", …]` or `{ "ignore": ["id", …] }`.
 *
 * A baseline the user explicitly passed but that can't be honored (missing
 * file, bad JSON, wrong shape) throws instead of degrading to "no baseline" —
 * silently un-suppressing findings would defeat the point in CI.
 */
export function loadBaseline(path: string | undefined): Baseline {
  if (!path) return { ignore: new Set() };
  const text = readTextSafe(path);
  if (text === null) throw new Error(`baseline file not found or unreadable: ${path}`);
  const json = parseJsonSafe<unknown>(text);
  if (json === null) throw new Error(`baseline file is not valid JSON: ${path}`);
  const ids: unknown = Array.isArray(json) ? json : (json as { ignore?: unknown })?.ignore;
  if (!Array.isArray(ids) || !ids.every((x): x is string => typeof x === "string")) {
    throw new Error(`baseline must be ["<finding-id>", …] or { "ignore": [ … ] }: ${path}`);
  }
  return { ignore: new Set(ids) };
}

/**
 * Serialize findings into baseline JSON (the `{ "ignore": [...] }` shape),
 * ids deduped and sorted so the file diffs cleanly under version control.
 */
export function renderBaseline(findings: Finding[]): string {
  const ids = [...new Set(findings.map((f) => f.id))].sort();
  return `${JSON.stringify({ ignore: ids }, null, 2)}\n`;
}

export function applyBaseline(findings: Finding[], baseline: Baseline): { kept: Finding[]; suppressed: Finding[] } {
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    (baseline.ignore.has(f.id) ? suppressed : kept).push(f);
  }
  return { kept, suppressed };
}
