/** Baseline suppression: accept known findings so repeat runs stay quiet. */
import type { Finding } from "./model.js";
import { parseJsonSafe, readTextSafe } from "./util.js";

export interface Baseline {
  ignore: Set<string>;
}

/** Accepts either `["id", …]` or `{ "ignore": ["id", …] }`. */
export function loadBaseline(path: string | undefined): Baseline {
  if (!path) return { ignore: new Set() };
  const text = readTextSafe(path);
  if (text === null) return { ignore: new Set() };
  const json = parseJsonSafe<any>(text);
  const ids: unknown[] = Array.isArray(json)
    ? json
    : Array.isArray(json?.ignore)
      ? json.ignore
      : [];
  return { ignore: new Set(ids.filter((x): x is string => typeof x === "string")) };
}

export function applyBaseline(
  findings: Finding[],
  baseline: Baseline,
): { kept: Finding[]; suppressed: Finding[] } {
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    (baseline.ignore.has(f.id) ? suppressed : kept).push(f);
  }
  return { kept, suppressed };
}
