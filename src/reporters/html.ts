/**
 * Self-contained HTML reporter.
 *
 * Design: a light "classified dossier" — an ink masthead over warm-neutral
 * paper. Color carries meaning (a severity temperature ramp), the display voice
 * is monospace (the tool's CLI/config world), and the signature motif is the
 * redaction bar standing in for every secret fingerprint.
 *
 * Emits a single file with all CSS inlined and no external assets, so it works
 * both as a local `--out report.html` and under a strict CSP.
 */
import type { AuditReport, Finding, Severity, ToolId } from "../model.js";
import { SEVERITY_ORDER } from "../severity.js";

export interface HtmlOptions {
  findings: Finding[];
  suppressedCount: number;
  minSeverity: Severity;
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const HTML_CSS = `
:root{
  --paper:#E7E5DC; --panel:#F1EFE8; --ink:#17140F; --ink-2:#524D43; --rule:#CFCBC0;
  --crit:#A5102A; --high:#C6541F; --med:#AE821F; --low:#3F5E7A; --info:#837D71;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
  -webkit-font-smoothing:antialiased;line-height:1.5}
.wrap{max-width:900px;margin:0 auto;padding:0 24px 96px}
a{color:var(--low)}
.sev-critical{--c:var(--crit)} .sev-high{--c:var(--high)} .sev-medium{--c:var(--med)}
.sev-low{--c:var(--low)} .sev-info{--c:var(--info)}

/* masthead */
.masthead{background:var(--ink);color:var(--paper);margin:0 -24px 40px;padding:36px 24px 30px}
.mast-inner{max-width:900px;margin:0 auto}
.brand{font-family:var(--mono);font-weight:700;font-size:1.5rem;letter-spacing:.04em;
  display:flex;align-items:center;gap:.6em}
.brand .bars{display:inline-flex;gap:3px}
.brand .bars i{display:block;width:14px;height:16px;background:var(--paper);opacity:.9}
.brand .bars i:last-child{width:7px;opacity:.5}
.dossier{font-family:var(--mono);font-size:.72rem;letter-spacing:.2em;text-transform:uppercase;
  color:#B7B1A3;margin:16px 0 0}
.thesis{font-size:1.06rem;max-width:60ch;margin:10px 0 24px;color:#E9E5DB}
.tally{display:flex;flex-wrap:wrap;gap:8px}
.seg{font-family:var(--mono);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;
  display:inline-flex;align-items:center;gap:7px;padding:6px 11px;border:1px solid #3a352c;border-radius:2px}
.seg b{font-size:.86rem}
.seg .dot{width:9px;height:9px;border-radius:1px;background:var(--c,#888)}
.seg.none{color:#B7B1A3;border-color:#3a352c}

/* section headings */
.eyebrow{font-family:var(--mono);font-size:.72rem;letter-spacing:.2em;text-transform:uppercase;
  color:var(--ink-2);margin:44px 0 14px;padding-bottom:9px;border-bottom:1px solid var(--rule)}

/* tools ledger */
.tools{display:flex;flex-direction:column;gap:1px;background:var(--rule);border:1px solid var(--rule);border-radius:3px;overflow:hidden}
.trow{display:flex;justify-content:space-between;align-items:baseline;gap:16px;background:var(--panel);padding:12px 15px;flex-wrap:wrap}
.trow .name{font-family:var(--mono);font-weight:600;font-size:.92rem;display:flex;align-items:center;gap:9px}
.trow .name .mark{width:8px;height:8px;border-radius:50%;background:var(--ink)}
.trow.off .name{color:var(--ink-2)}
.trow.off .name .mark{background:none;border:1px solid var(--ink-2)}
.trow .counts{font-family:var(--mono);font-size:.74rem;color:var(--ink-2);letter-spacing:.02em}
.trow .off-label{font-family:var(--mono);font-size:.74rem;color:var(--ink-2);font-style:italic}

/* findings */
.finding{background:var(--panel);border:1px solid var(--rule);border-left:4px solid var(--c,var(--rule));
  border-radius:3px;padding:16px 18px;margin:14px 0}
.f-head{display:flex;align-items:center;gap:11px;flex-wrap:wrap}
.chip{font-family:var(--mono);font-size:.66rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:#fff;background:var(--c,#888);padding:3px 8px;border-radius:2px}
.f-title{font-weight:600;font-size:1.04rem;margin:0}
.f-meta{font-family:var(--mono);font-size:.71rem;color:var(--ink-2);margin:9px 0 0;letter-spacing:.02em}
.f-rationale{font-size:.93rem;margin:11px 0 0;color:#26221b}
.excerpt{font-family:var(--mono);font-size:.76rem;background:var(--paper);border:1px solid var(--rule);
  border-radius:2px;padding:9px 11px;margin:12px 0 0;overflow-x:auto;color:#2c2820}
.excerpt .path{color:var(--low)}
.excerpt .loc{color:var(--ink-2)}
.redbar{display:inline-block;width:4.6em;height:.86em;background:var(--ink);vertical-align:-1px;
  border-radius:2px;margin-right:.55em}
.fix{font-size:.9rem;margin:12px 0 0;display:flex;gap:.6em}
.fix .k{font-family:var(--mono);font-size:.68rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--ink);background:var(--paper);border:1px solid var(--rule);padding:2px 7px;border-radius:2px;height:fit-content;white-space:nowrap}
.clean{font-size:.95rem;color:var(--ink-2);padding:8px 0}

/* notes + footer */
.notes{font-family:var(--mono);font-size:.75rem;color:var(--ink-2);margin-top:10px}
.foot{margin-top:56px;padding-top:16px;border-top:1px solid var(--rule);
  font-family:var(--mono);font-size:.71rem;color:var(--ink-2);letter-spacing:.02em;line-height:1.7}
.foot .legend{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:10px}
.foot .lg{display:inline-flex;align-items:center;gap:6px;text-transform:uppercase;letter-spacing:.08em}
.foot .lg .dot{width:9px;height:9px;border-radius:1px;background:var(--c)}

.finding{animation:rise .4s ease both}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
:focus-visible{outline:2px solid var(--low);outline-offset:2px}
@media (prefers-reduced-motion:reduce){.finding{animation:none}}
@media (max-width:640px){.wrap{padding:0 16px 72px}.masthead{margin:0 -16px 32px;padding:28px 16px 24px}
  .brand{font-size:1.25rem}.trow{gap:6px}}
`;

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

function toolCounts(report: AuditReport, id: ToolId): string {
  const inv = report.inventory;
  const n = (arr: { tool: ToolId }[]) => arr.filter((x) => x.tool === id).length;
  return [
    `${n(inv.mcpServers)} MCP`,
    `${n(inv.grants)} grants`,
    `${n(inv.hooks)} hooks`,
    `${n(inv.contextSources)} context`,
    `${n(inv.credentials)} creds`,
  ].join("  ·  ");
}

function isSecretRule(ruleId: string): boolean {
  return ruleId.startsWith("secret-");
}

function renderEvidence(f: Finding): string {
  return f.evidence
    .map((e) => {
      const loc = e.locator ? ` <span class="loc">(${esc(e.locator)})</span>` : "";
      const bar = isSecretRule(f.ruleId) ? '<span class="redbar" aria-label="redacted secret"></span>' : "";
      const snip = e.redactedSnippet ? `<div>${bar}${esc(e.redactedSnippet)}</div>` : "";
      return `<div class="excerpt"><div><span class="path">${esc(e.path)}</span>${loc}</div>${snip}</div>`;
    })
    .join("");
}

function renderFinding(f: Finding): string {
  return `
  <article class="finding sev-${f.severity}">
    <div class="f-head">
      <span class="chip">${esc(SEV_LABEL[f.severity])}</span>
      <h3 class="f-title">${esc(f.title)}</h3>
    </div>
    <p class="f-meta">${esc(f.tool)} · ${esc(f.ruleId)} · confidence ${esc(f.confidence)}</p>
    <p class="f-rationale">${esc(f.rationale)}</p>
    ${renderEvidence(f)}
    <p class="fix"><span class="k">Fix</span><span>${esc(f.remediation)}</span></p>
  </article>`;
}

/** Body markup + a leading <style>. Suitable for embedding (e.g. an Artifact). */
export function renderHtmlContent(report: AuditReport, opts: HtmlOptions): string {
  const counts = countBySeverity(opts.findings);
  const total = opts.findings.length;

  const tally = SEVERITY_ORDER.map((s) =>
    counts[s]
      ? `<span class="seg sev-${s}"><span class="dot"></span><b>${counts[s]}</b> ${esc(SEV_LABEL[s])}</span>`
      : "",
  ).join("");
  const tallyBlock = total > 0 ? tally : `<span class="seg none">No findings at or above ${esc(opts.minSeverity)}</span>`;
  const suppressed = opts.suppressedCount > 0 ? `<span class="seg none">${opts.suppressedCount} suppressed</span>` : "";

  const toolRows = report.inventory.tools
    .map((t) =>
      t.installed
        ? `<div class="trow"><span class="name"><span class="mark"></span>${esc(t.displayName)}</span><span class="counts">${esc(toolCounts(report, t.id))}</span></div>`
        : `<div class="trow off"><span class="name"><span class="mark"></span>${esc(t.displayName)}</span><span class="off-label">not installed</span></div>`,
    )
    .join("");

  const findingsBlock =
    total > 0
      ? opts.findings.map(renderFinding).join("")
      : `<p class="clean">Nothing to report at or above <b>${esc(opts.minSeverity)}</b> severity. Lower <code>--min-severity</code> to see informational items.</p>`;

  const notes =
    report.inventory.errors.length > 0
      ? `<p class="notes">Notes: ${report.inventory.errors.map((e) => esc(`[${e.tool}] ${e.message}`)).join(" · ")}</p>`
      : "";

  const legend = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => `<span class="lg sev-${s}"><span class="dot"></span>${esc(SEV_LABEL[s])}</span>`)
    .join("");

  return `<style>${HTML_CSS}</style>
<div class="masthead"><div class="mast-inner">
  <div class="brand">skopecreep <span class="bars" aria-hidden="true"><i></i><i></i><i></i></span></div>
  <p class="dossier">AI Tooling Scope Audit · ${esc(report.host.platform)} · ${esc(report.generatedAt)}</p>
  <p class="thesis">Everything your AI coding tools can do, and everything they've been told — with the risky configuration ranked and explained. Secrets are always redacted.</p>
  <div class="tally">${tallyBlock}${suppressed}</div>
</div></div>
<div class="wrap">
  <h2 class="eyebrow">Tools detected</h2>
  <div class="tools">${toolRows}</div>

  <h2 class="eyebrow">Findings${total > 0 ? ` — ${total}` : ""}</h2>
  ${findingsBlock}
  ${notes}

  <footer class="foot">
    <div class="legend">${legend}</div>
    Severity = impact × (exposure + exploitability). Redaction bars mark values shown only as a fingerprint — never the secret itself.<br>
    Generated by skopecreep · read-only · report data stays on your machine.
  </footer>
</div>`;
}

/** Full standalone HTML document (for `--out report.html`). */
export function renderHtml(report: AuditReport, opts: HtmlOptions): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>skopecreep — AI tooling scope audit</title>
</head>
<body>
${renderHtmlContent(report, opts)}
</body>
</html>`;
}
