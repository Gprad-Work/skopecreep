/**
 * Calibrated severity model.
 *
 * The product's whole value is *not* over-flagging. We score every finding as
 * classic risk = likelihood × impact, where likelihood is split into how
 * reachable the issue is (exposure) and how easily it can be triggered
 * (exploitability). Detectors supply the three dimensions; they never hardcode
 * a severity label. Because impact is a multiplier, a zero-impact observation
 * (e.g. a non-secret cloudId) can never escalate above `info` no matter how
 * exposed it is — that is the specific false-positive class we refuse to ship.
 */
import type { CredentialAtRest, Severity } from "./model.js";

/** 0 = none, 1 = low, 2 = moderate, 3 = severe. */
export type Dim = 0 | 1 | 2 | 3;

export interface SeverityInput {
  /** consequence if abused (0 none → 3 full account/RCE) */
  impact: Dim;
  /** how reachable/leaked it is (0 not reachable → 3 world-readable / in VCS) */
  exposure: Dim;
  /** how easily it can be triggered (0 needs deep compromise → 3 trivial) */
  exploitability: Dim;
}

/** risk in [0, 18] */
export function riskScore({ impact, exposure, exploitability }: SeverityInput): number {
  return impact * (exposure + exploitability);
}

export function computeSeverity(input: SeverityInput): Severity {
  const r = riskScore(input);
  if (r <= 1) return "info";
  if (r <= 5) return "low";
  if (r <= 9) return "medium";
  if (r <= 13) return "high";
  return "critical";
}

const RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityRank(s: Severity): number {
  return RANK[s];
}

export function meetsMin(s: Severity, min: Severity): boolean {
  return RANK[s] >= RANK[min];
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return RANK[a] >= RANK[b] ? a : b;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Map a credential file's on-disk situation to an exposure dimension. This is
 * why the same token is `medium` at 600-perms in $HOME but `critical` once it
 * lands in a git repo or a synced folder.
 */
export function exposureFromFile(cred: CredentialAtRest): Dim {
  if (cred.inVcsOrSyncedDir) return 3;
  if (cred.worldOrGroupReadable) return 3;
  if (cred.perms === "unknown") return 2; // Windows: can't prove it's locked down
  return 1; // owner-only in a normal home dir
}
