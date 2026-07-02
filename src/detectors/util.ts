import { sha256, statInfo, isInVcsOrSyncedDir } from "../util.js";
import type { Dim } from "../severity.js";

/** Stable id for baselining: same finding across runs → same id. */
export function makeFindingId(ruleId: string, parts: string[]): string {
  return sha256(`${ruleId}|${parts.join("|")}`).slice(0, 12);
}

/** Exposure dimension for any file, from its perms + VCS/synced-dir membership. */
export function exposureForPath(p: string): Dim {
  if (isInVcsOrSyncedDir(p)) return 3;
  const st = statInfo(p);
  if (st?.worldOrGroupReadable) return 3;
  if (!st || st.perms === "unknown") return 2;
  return 1;
}
