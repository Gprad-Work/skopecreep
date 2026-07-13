/**
 * Creep detection — the tool's namesake. A snapshot records the machine's
 * posture (finding ids + a stable key per granted capability); a later scan
 * diffed against it answers the question no point-in-time report can:
 * "what got granted since I last looked?"
 */
import type { AuditReport, Finding } from "./model.js";
import { parseJsonSafe, readTextSafe } from "./util.js";

export interface Snapshot {
  schemaVersion: 1;
  takenAt: string;
  findingIds: string[];
  /** stable keys for granted surface: mcp servers, grants, hooks, credentials */
  inventoryKeys: string[];
}

/** Stable, human-readable keys — order-independent and diff-friendly. */
export function inventoryKeys(report: AuditReport): string[] {
  const inv = report.inventory;
  const keys = [
    ...inv.mcpServers.map((s) => `mcp:${s.tool}/${s.name}`),
    ...inv.grants.map((g) => `grant:${g.tool}|${g.kind}|${g.value}${g.scope ? `|${g.scope}` : ""}`),
    ...inv.hooks.map((h) => `hook:${h.tool}|${h.event}|${h.command}`),
    ...inv.credentials.map((c) => `cred:${c.tool}|${c.path}`),
  ];
  return [...new Set(keys)].sort();
}

export function takeSnapshot(report: AuditReport): Snapshot {
  return {
    schemaVersion: 1,
    takenAt: report.generatedAt,
    findingIds: [...new Set(report.findings.map((f) => f.id))].sort(),
    inventoryKeys: inventoryKeys(report),
  };
}

export function renderSnapshot(report: AuditReport): string {
  return `${JSON.stringify(takeSnapshot(report), null, 2)}\n`;
}

/** Same hard-error contract as loadBaseline: a snapshot you passed but can't use is an error. */
export function loadSnapshot(path: string): Snapshot {
  const text = readTextSafe(path);
  if (text === null) throw new Error(`snapshot file not found or unreadable: ${path}`);
  const json = parseJsonSafe<Partial<Snapshot>>(text);
  if (
    json === null ||
    json.schemaVersion !== 1 ||
    !Array.isArray(json.findingIds) ||
    !Array.isArray(json.inventoryKeys)
  ) {
    throw new Error(`not a skopecreep snapshot (need schemaVersion 1 with findingIds/inventoryKeys): ${path}`);
  }
  return json as Snapshot;
}

export interface Creep {
  since: string;
  newFindings: Finding[];
  newInventoryKeys: string[];
  removedInventoryKeys: string[];
}

export function diffSnapshot(report: AuditReport, snapshot: Snapshot): Creep {
  const oldFindings = new Set(snapshot.findingIds);
  const oldKeys = new Set(snapshot.inventoryKeys);
  const nowKeys = inventoryKeys(report);
  const nowKeySet = new Set(nowKeys);
  return {
    since: snapshot.takenAt,
    newFindings: report.findings.filter((f) => !oldFindings.has(f.id)),
    newInventoryKeys: nowKeys.filter((k) => !oldKeys.has(k)),
    removedInventoryKeys: snapshot.inventoryKeys.filter((k) => !nowKeySet.has(k)),
  };
}
