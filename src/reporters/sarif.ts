/**
 * SARIF 2.1.0 reporter — hand-rolled JSON (SARIF is just a shape; no new
 * runtime dependency). Built for GitHub code scanning ingestion:
 * `security-severity` drives GitHub's severity chips, `partialFingerprints`
 * reuses the stable baseline finding id so re-uploads dedupe, and evidence
 * paths under the scanned project are relativized so alerts annotate files.
 * Findings outside the checkout (home-dir config) keep absolute URIs — valid
 * SARIF, listed but not annotated.
 */
import { createRequire } from "node:module";
import * as path from "node:path";
import type { AuditReport, Finding, Severity } from "../model.js";
import { REMEDIATION_TIERS } from "../model.js";

export interface SarifOptions {
  findings: Finding[];
  suppressedCount: number;
  minSeverity: Severity;
  /** scanned project dir; evidence under it becomes repo-relative URIs */
  projectPath?: string;
}

const VERSION: string = createRequire(import.meta.url)("../../package.json").version;

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** GitHub's numeric severity scale (0-10); drives its critical/high/… chips. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "1.0",
};

function evidenceUri(p: string, projectPath?: string): { uri: string; uriBaseId?: string } {
  if (projectPath) {
    const rel = path.relative(projectPath, p);
    if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) {
      return { uri: rel.split(path.sep).join("/"), uriBaseId: "PROJECTROOT" };
    }
  }
  return { uri: `file://${p.split(path.sep).join("/")}` };
}

function startLine(locator: string | undefined): number | undefined {
  const m = /^line (\d+)$/.exec(locator ?? "");
  return m ? Number(m[1]) : undefined;
}

function helpText(f: Finding): string {
  return REMEDIATION_TIERS.map((t) => `${t}: ${f.remediation[t]}`).join("\n\n");
}

export function renderSarif(report: AuditReport, opts: SarifOptions): string {
  // One reportingDescriptor per ruleId, built from the first finding seen.
  const ruleIndex = new Map<string, number>();
  const rules: object[] = [];
  for (const f of opts.findings) {
    if (ruleIndex.has(f.ruleId)) continue;
    ruleIndex.set(f.ruleId, rules.length);
    rules.push({
      id: f.ruleId,
      shortDescription: { text: f.title },
      help: { text: helpText(f) },
      helpUri: f.atlas?.[0]?.url,
      properties: {
        "security-severity": SECURITY_SEVERITY[f.severity],
        tags: ["security", ...(f.atlas ?? []).map((a) => a.techniqueId)],
      },
    });
  }

  const results = opts.findings.map((f) => {
    const locations = f.evidence.map((e) => {
      const line = startLine(e.locator);
      return {
        physicalLocation: {
          artifactLocation: evidenceUri(e.path, opts.projectPath),
          ...(line !== undefined ? { region: { startLine: line } } : {}),
        },
        ...(e.locator && line === undefined ? { message: { text: e.locator } } : {}),
      };
    });
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId),
      level: LEVEL[f.severity],
      message: { text: `${f.title}. ${f.rationale}` },
      locations,
      partialFingerprints: { "skopecreepFindingId/v1": f.id },
      properties: {
        severity: f.severity,
        confidence: f.confidence,
        tool: f.tool,
        atlas: f.atlas ?? [],
        redactedSnippets: f.evidence.map((e) => e.redactedSnippet).filter(Boolean),
        ...(f.related ? { chainMembers: f.related } : {}),
      },
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "skopecreep",
            semanticVersion: VERSION,
            informationUri: "https://github.com/Gprad-Work/skopecreep",
            rules,
          },
        },
        ...(opts.projectPath
          ? {
              originalUriBaseIds: {
                PROJECTROOT: { uri: `file://${opts.projectPath.split(path.sep).join("/")}/` },
              },
            }
          : {}),
        results,
        properties: {
          generatedAt: report.generatedAt,
          platform: report.host.platform,
          suppressedCount: opts.suppressedCount,
          minSeverity: opts.minSeverity,
        },
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
