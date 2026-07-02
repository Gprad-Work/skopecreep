/**
 * Context integrity: prompt-injection signals, hidden Unicode, embedded
 * payloads, and external-file dependencies in the instruction/memory files that
 * steer the agent. These are heuristics -> deliberately medium/low confidence,
 * so a human reviews rather than the tool asserting malice.
 */
import type { ContextSource, Finding } from "../model.js";
import type { Detector } from "./types.js";
import { computeSeverity } from "../severity.js";
import { makeFindingId } from "./util.js";
import { evidenceSnippet } from "../secrets/redact.js";

const HIGH_PHRASES = [
  { re: /do\s+not\s+(?:tell|inform|reveal\s+to|mention\s+to|notify)\s+the\s+user/i, name: "conceal an action from the user" },
  { re: /exfiltrat/i, name: "exfiltration" },
  {
    re: /\b(?:send|post|upload|leak|forward)\b[^.\n]{0,50}\b(?:secrets?|credentials?|tokens?|api[\s_-]?keys?|\.env|environment variables?|private key)\b/i,
    name: "send secrets/credentials somewhere",
  },
];
const MED_PHRASES = [
  { re: /ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|messages?|rules?)/i, name: "override previous instructions" },
  { re: /disregard\s+(?:the\s+|all\s+)?(?:above|previous|prior|earlier)\b/i, name: "disregard previous context" },
];

// Regexes for invisible characters are built via RegExp() from escaped strings
// so the SOURCE never contains an actual invisible/bidi character.
// Bidirectional overrides (Trojan-Source): U+202A-U+202E, U+2066-U+2069.
const BIDI = new RegExp("[\\u202A-\\u202E\\u2066-\\u2069]", "gu");
// Zero-width / invisible marks: U+200B, U+200C, U+200E, U+200F, U+2060-U+2064.
// Excludes U+200D (ZWJ, used in emoji) and U+FEFF (BOM).
const ZERO_WIDTH = new RegExp("[\\u200B\\u200C\\u200E\\u200F\\u2060-\\u2064]", "gu");
const BASE64_BLOB = /[A-Za-z0-9+/]{200,}={0,2}/;
const EXTERNAL_DEP =
  /(?:read|open|load|execute|run|source|include)\s+[`'"]?((?:\/|~\/|\.\.\/)[^\s`'"]+\.(?:ya?ml|sh|bash|zsh|py|js|ts|rb|json|toml))/i;

function firstMatchingLine(content: string, re: RegExp): string {
  for (const line of content.split(/\r?\n/)) {
    if (re.test(line)) return evidenceSnippet(line);
  }
  return "";
}

function scanOne(ctx: ContextSource): Finding[] {
  const out: Finding[] = [];
  const { content } = ctx;
  if (!content) return out;

  // 1. Injection phrases (highest tier matched wins, one finding per file).
  const highHits = HIGH_PHRASES.filter((p) => p.re.test(content)).map((p) => p.name);
  const medHits = MED_PHRASES.filter((p) => p.re.test(content)).map((p) => p.name);
  if (highHits.length > 0 || medHits.length > 0) {
    const high = highHits.length > 0;
    const names = high ? highHits : medHits;
    const sampleRe = high
      ? HIGH_PHRASES.find((p) => p.re.test(content))!.re
      : MED_PHRASES.find((p) => p.re.test(content))!.re;
    out.push({
      id: makeFindingId("context-injection", [ctx.tool, ctx.path, names.join(",")]),
      ruleId: "context-injection",
      tool: ctx.tool,
      severity: computeSeverity({ impact: high ? 3 : 2, exposure: 3, exploitability: 1 }),
      confidence: "medium",
      title: `Possible prompt-injection language in ${ctx.role} file`,
      rationale:
        `${ctx.path} contains phrasing that resembles an injected instruction (${names.join("; ")}). ` +
        `Because this file is loaded into the agent's context automatically, hostile instructions here execute silently. ` +
        `Confirm this is legitimate guidance and not attacker-supplied content.`,
      remediation: `Review the file. If you didn't author this passage (e.g. it arrived via a cloned repo or shared config), remove it.`,
      evidence: [{ path: ctx.path, redactedSnippet: firstMatchingLine(content, sampleRe) }],
    });
  }

  // 2. Hidden / bidirectional Unicode.
  const bidi = (content.match(BIDI) ?? []).length;
  const zw = (content.match(ZERO_WIDTH) ?? []).length;
  if (bidi > 0 || zw >= 3) {
    const strong = bidi > 0 || zw >= 5;
    out.push({
      id: makeFindingId("context-hidden-unicode", [ctx.tool, ctx.path]),
      ruleId: "context-hidden-unicode",
      tool: ctx.tool,
      severity: computeSeverity({ impact: 3, exposure: 3, exploitability: strong ? 1 : 0 }),
      confidence: "medium",
      title: `Hidden/bidirectional Unicode in ${ctx.role} file`,
      rationale:
        `${ctx.path} contains ${bidi} bidirectional-override and ${zw} zero-width character(s). These are invisible in most ` +
        `editors and are a known way to hide instructions (Trojan Source) inside a file the agent reads verbatim.`,
      remediation: `Inspect the file with a tool that reveals invisible characters and strip any you didn't intentionally add.`,
      evidence: [{ path: ctx.path, redactedSnippet: `${bidi} bidi + ${zw} zero-width chars` }],
    });
  }

  // 3. Large embedded base64 payload.
  if (BASE64_BLOB.test(content)) {
    out.push({
      id: makeFindingId("context-base64-blob", [ctx.tool, ctx.path]),
      ruleId: "context-base64-blob",
      tool: ctx.tool,
      severity: computeSeverity({ impact: 2, exposure: 3, exploitability: 1 }),
      confidence: "low",
      title: `Large base64 blob embedded in ${ctx.role} file`,
      rationale:
        `${ctx.path} embeds a long base64 string. That can be benign (an inline image) or a hidden/obfuscated payload the ` +
        `agent might be told to decode and run.`,
      remediation: `Confirm what the blob decodes to; move legitimate binary assets out of instruction files.`,
      evidence: [{ path: ctx.path, redactedSnippet: "base64 blob >=200 chars (not shown)" }],
    });
  }

  // 4. Instruction depends on an external file (supply-chain of instructions).
  if ((ctx.role === "instructions" || ctx.role === "rule") && EXTERNAL_DEP.test(content)) {
    out.push({
      id: makeFindingId("context-external-dep", [ctx.tool, ctx.path]),
      ruleId: "context-external-dep",
      tool: ctx.tool,
      severity: computeSeverity({ impact: 1, exposure: 1, exploitability: 1 }),
      confidence: "low",
      title: `Instructions depend on an external file`,
      rationale:
        `${ctx.path} instructs the agent to read/run an external file before acting. Whoever controls that file effectively ` +
        `controls part of the agent's behavior — a subtle supply-chain link worth being aware of.`,
      remediation: `Ensure the referenced file is under your control and integrity-checked, or inline the guidance.`,
      evidence: [{ path: ctx.path, redactedSnippet: firstMatchingLine(content, EXTERNAL_DEP) }],
    });
  }

  return out;
}

export const detectContextInjection: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const ctx of inv.contextSources) findings.push(...scanOne(ctx));
  return findings;
};
