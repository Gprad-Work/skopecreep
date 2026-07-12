/**
 * Context integrity: prompt-injection signals, hidden Unicode, embedded
 * payloads, external-file dependencies, self-replicating instructions, and
 * system-prompt extraction probes in the instruction/memory files that
 * steer the agent. These are heuristics -> deliberately medium/low confidence,
 * so a human reviews rather than the tool asserting malice.
 */
import type { ContextSource, Finding } from "../model.js";
import { evidenceSnippet } from "../secrets/redact.js";
import { computeSeverity } from "../severity.js";
import type { Detector } from "./types.js";
import { makeFindingId } from "./util.js";

const HIGH_PHRASES = [
  {
    re: /do\s+not\s+(?:tell|inform|reveal\s+to|mention\s+to|notify)\s+the\s+user/i,
    name: "conceal an action from the user",
  },
  { re: /exfiltrat/i, name: "exfiltration" },
  {
    re: /\b(?:send|post|upload|leak|forward)\b[^.\n]{0,50}\b(?:secrets?|credentials?|tokens?|api[\s_-]?keys?|\.env|environment variables?|private key)\b/i,
    name: "send secrets/credentials somewhere",
  },
];
const MED_PHRASES = [
  {
    re: /ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|messages?|rules?)/i,
    name: "override previous instructions",
  },
  { re: /disregard\s+(?:the\s+|all\s+)?(?:above|previous|prior|earlier)\b/i, name: "disregard previous context" },
];

// Regexes for invisible characters are built via RegExp() from escaped strings
// so the SOURCE never contains an actual invisible/bidi character.
// Bidirectional overrides (Trojan-Source): U+202A-U+202E, U+2066-U+2069.
const BIDI = /[\u202A-\u202E\u2066-\u2069]/gu;
// Zero-width / invisible marks: U+200B, U+200C, U+200E, U+200F, U+2060-U+2064.
// Excludes U+200D (ZWJ, used in emoji) and U+FEFF (BOM).
const ZERO_WIDTH = /[\u200B\u200C\u200E\u200F\u2060-\u2064]/gu;
const BASE64_BLOB = /[A-Za-z0-9+/]{200,}={0,2}/;
const EXTERNAL_DEP =
  /(?:read|open|load|execute|run|source|include)\s+[`'"]?((?:\/|~\/|\.\.\/)[^\s`'"]+\.(?:ya?ml|sh|bash|zsh|py|js|ts|rb|json|toml))/i;
// Worm behavior: the file tells the agent to propagate its own instructions
// into other context files / repos (ATLAS AML.T0061 LLM Prompt Self-Replication).
const SELF_REPLICATION =
  /\b(?:add|copy|append|insert|write|inject|propagate|replicate|duplicate)\b[^.\n]{0,60}\b(?:these\s+(?:instructions|rules)|this\s+(?:file|prompt|rule|instruction|section)|itself)\b[^.\n]{0,80}\b(?:CLAUDE\.md|AGENTS\.md|\.cursorrules|\.windsurfrules|copilot-instructions|(?:other|every|all|any)\s+(?:repo|project|file|workspace)\w*)/i;
// Extraction probe: the file tells the agent to disclose its system prompt /
// hidden instructions (ATLAS AML.T0056 / AML.T0069.002). "initial/hidden
// instructions" requires a possessive (your/its) so ordinary prose like
// "show the initial instructions to new contributors" doesn't trip it.
const SYSTEM_PROMPT_PROBE =
  /\b(?:reveal|print|show|output|repeat|dump|display|echo|disclose|paste)\b[^.\n]{0,40}\b(?:system\s+prompt|(?:your|its)\s+(?:initial|hidden)\s+instructions?|developer\s+message|(?:text|instructions|everything)\s+above\s+this)\b/i;

function firstMatchingLine(lines: string[], re: RegExp): string {
  for (const line of lines) {
    if (re.test(line)) return evidenceSnippet(line);
  }
  return "";
}

function scanOne(ctx: ContextSource): Finding[] {
  const out: Finding[] = [];
  const { content } = ctx;
  if (!content) return out;
  // Context files can be large; split once and share across every rule below.
  const lines = content.split(/\r?\n/);

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
      remediation: {
        loose: `Read the flagged passage and confirm you (or a teammate) wrote it deliberately.`,
        medium: `If you didn't author it (e.g. it arrived via a cloned repo or shared config), delete the passage and diff the file against a version you trust.`,
        tight: `Delete the passage, treat the source repo/config as untrusted, and check git history plus your other context files for how it got in and whether it spread.`,
      },
      evidence: [{ path: ctx.path, redactedSnippet: firstMatchingLine(lines, sampleRe) }],
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
      remediation: {
        loose: `Open the file in a tool that reveals invisible characters and confirm the hidden characters are harmless (e.g. copy-paste artifacts).`,
        medium: `Strip every bidi/zero-width character you didn't intentionally add, then re-read the visible text for instructions that were being hidden.`,
        tight: `Strip the characters, audit how they got in (git blame the lines), and add a pre-commit/CI check that rejects bidi and zero-width characters in context files.`,
      },
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
      remediation: {
        loose: `Decode the blob yourself and confirm it's a benign asset (an image, a diagram) rather than text or code.`,
        medium: `Move legitimate binary assets out of instruction files and reference them by path instead of inlining them.`,
        tight: `Remove the blob entirely and keep instruction/memory files plain-text only, so encoded payloads have nowhere to hide.`,
      },
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
      remediation: {
        loose: `Read the referenced file now and confirm its content is what you expect.`,
        medium: `Inline the guidance into this file so there's no external dependency, or keep the referenced file in the same version-controlled repo.`,
        tight: `Inline the guidance and remove instructions that have the agent read/run files outside the project — context should be self-contained and reviewable in one place.`,
      },
      evidence: [{ path: ctx.path, redactedSnippet: firstMatchingLine(lines, EXTERNAL_DEP) }],
    });
  }

  // 5. Self-replication: instructions that propagate themselves (worm behavior).
  if (SELF_REPLICATION.test(content)) {
    out.push({
      id: makeFindingId("context-self-replication", [ctx.tool, ctx.path]),
      ruleId: "context-self-replication",
      tool: ctx.tool,
      severity: computeSeverity({ impact: 2, exposure: 3, exploitability: 2 }),
      confidence: "medium",
      title: `${ctx.role} file tells the agent to copy its instructions elsewhere`,
      rationale:
        `${ctx.path} instructs the agent to propagate its own instructions into other context files or repos. ` +
        `Self-replicating prompts are a persistence technique: one poisoned file quietly seeds every project the agent touches.`,
      remediation: {
        loose: `Confirm the propagation is something you set up on purpose (e.g. a deliberate template sync).`,
        medium: `Remove the propagation instruction; if you need shared guidance across repos, distribute it through version control instead.`,
        tight: `Remove the instruction and search every repo/workspace the agent has touched for copies it may already have planted.`,
      },
      evidence: [{ path: ctx.path, redactedSnippet: firstMatchingLine(lines, SELF_REPLICATION) }],
    });
  }

  // 6. System-prompt extraction probe.
  if (SYSTEM_PROMPT_PROBE.test(content)) {
    out.push({
      id: makeFindingId("context-system-prompt-probe", [ctx.tool, ctx.path]),
      ruleId: "context-system-prompt-probe",
      tool: ctx.tool,
      severity: computeSeverity({ impact: 2, exposure: 3, exploitability: 1 }),
      confidence: "medium",
      title: `${ctx.role} file asks the agent to disclose its system prompt`,
      rationale:
        `${ctx.path} contains an instruction to reveal the system prompt / hidden instructions. In a context file this is ` +
        `an extraction probe: the disclosed prompt ends up in output the file's author can read, mapping your setup for a follow-on attack.`,
      remediation: {
        loose: `Check whether this is your own debugging note; if so, consider removing it once you're done.`,
        medium: `Remove the extraction instruction — there's no legitimate reason for a persistent context file to dump the system prompt.`,
        tight: `Remove it and review where the agent's recent output went (PRs, logs, chat exports) to see if the prompt already leaked.`,
      },
      evidence: [{ path: ctx.path, redactedSnippet: firstMatchingLine(lines, SYSTEM_PROMPT_PROBE) }],
    });
  }

  return out;
}

export const detectContextInjection: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const ctx of inv.contextSources) findings.push(...scanOne(ctx));
  return findings;
};
