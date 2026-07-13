/** MCP supply-chain: unpinned package runners, remote code sources, and shell-as-server. */

import * as path from "node:path";
import type { Finding } from "../model.js";
import { evidenceSnippet } from "../secrets/redact.js";
import { computeSeverity } from "../severity.js";
import type { Detector } from "./types.js";
import { makeFindingId } from "./util.js";

const SHELLS = new Set(["bash", "sh", "zsh", "fish"]);

// Code pulled straight from a moving remote ref: git URLs, github: shorthands,
// or a script/archive URL passed to a runner. A 7+ hex commit pin (@<sha> or
// #<sha>) makes the ref immutable, so those are not flagged. The pin is
// checked on the source token itself, not the whole command line — an
// incidental hex token elsewhere must not vouch for the ref.
const REMOTE_CODE_SOURCE =
  /(?:git\+https?:\/\/|\bgithub:|https?:\/\/[^\s"']+\.(?:sh|bash|py|js|mjs|ts|tar\.gz|tgz|zip|whl))/i;
const COMMIT_PIN = /[@#][0-9a-f]{7,40}(?:$|["'])/i;

/** "@scope/name@1.2.3" | "name@latest" → "@scope/name" | "name" */
function specName(spec: string): string {
  const scoped = spec.startsWith("@");
  const body = scoped ? spec.slice(1) : spec;
  const at = body.indexOf("@");
  const name = at === -1 ? body : body.slice(0, at);
  return scoped ? `@${name}` : name;
}

export const detectMcpSupplyChain: Detector = (inv) => {
  const findings: Finding[] = [];
  for (const s of inv.mcpServers) {
    if (s.transport !== "stdio" || !s.command) continue;
    const cmdline = `${s.command} ${(s.args ?? []).join(" ")}`.trim();

    // Classify each server once: a git/URL code source is judged by the
    // remote-code-source rule alone; registry-style pinning (`@latest`, bare
    // name) doesn't apply to it, so the unpinned-package rule stands down —
    // otherwise `github:user/repo` double-flags and `github:user/repo#<sha>`
    // (no `@version`, but immutable) false-positives as unpinned.
    const remoteTokens = cmdline.split(/\s+/).filter((t) => REMOTE_CODE_SOURCE.test(t));

    if (remoteTokens.length === 0 && s.packageSpec && s.pinned === false) {
      findings.push({
        id: makeFindingId("mcp-unpinned-package", [s.tool, s.name, s.packageSpec]),
        ruleId: "mcp-unpinned-package",
        tool: s.tool,
        severity: computeSeverity({ impact: 3, exposure: 2, exploitability: 1 }),
        confidence: "high",
        title: `MCP server "${s.name}" auto-installs an unpinned package (${s.packageSpec})`,
        rationale:
          `"${s.name}" runs \`${evidenceSnippet(cmdline)}\`, which resolves "${s.packageSpec}" fresh from a public registry on every launch. ` +
          `An unpinned dependency means a compromised, hijacked, or typosquatted release would execute with your privileges inside the agent.`,
        remediation: {
          loose: `Pin at least the major version (e.g. "${specName(s.packageSpec)}@1") so a hijacked release can't jump you across majors silently.`,
          medium: `Pin the exact version instead of "@latest" or a bare name, and bump it deliberately.`,
          tight: `Pin the exact version and install it once into a local, lockfile-managed directory (or vendor it), so nothing is fetched from the registry at launch time.`,
        },
        evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: evidenceSnippet(cmdline) }],
      });
    }

    if (remoteTokens.some((t) => !COMMIT_PIN.test(t))) {
      findings.push({
        id: makeFindingId("mcp-remote-code-source", [s.tool, s.name]),
        ruleId: "mcp-remote-code-source",
        tool: s.tool,
        severity: computeSeverity({ impact: 3, exposure: 2, exploitability: 1 }),
        confidence: "high",
        title: `MCP server "${s.name}" runs code from a remote URL/git ref without a commit pin`,
        rationale:
          `"${s.name}" launches \`${evidenceSnippet(cmdline)}\`, which pulls code from a remote source that can change under you ` +
          `(a branch, a raw URL). Whoever controls that endpoint can swap the code for the next launch — same class of risk as an unpinned package, ` +
          `but without even a registry's audit trail.`,
        remediation: {
          loose: `Review what the URL/ref currently serves and note the commit you vetted.`,
          medium: `Pin the reference to that exact commit SHA (git+...@<sha> / #<sha>) so the code can't silently change.`,
          tight: `Clone/vendor the code locally after review and run it from the local path — no network fetch at launch at all.`,
        },
        evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: evidenceSnippet(cmdline) }],
      });
    }

    const base = path.basename(s.command).toLowerCase();
    if (SHELLS.has(base)) {
      findings.push({
        id: makeFindingId("mcp-shell-server", [s.tool, s.name]),
        ruleId: "mcp-shell-server",
        tool: s.tool,
        severity: computeSeverity({ impact: 3, exposure: 2, exploitability: 2 }),
        confidence: "high",
        title: `MCP server "${s.name}" is launched via a shell`,
        rationale:
          `"${s.name}" starts with \`${evidenceSnippet(cmdline)}\`. Running an MCP server through a shell (inline \`-c\`, piped scripts) ` +
          `is an easy vector for arbitrary command execution and obscures what actually runs.`,
        remediation: {
          loose: `Read the full shell line and confirm every command in it is one you put there.`,
          medium: `Run the server binary directly with explicit args instead of a \`sh -c\`/\`bash -c\` wrapper.`,
          tight: `Run the binary directly, pin its version, and launch it under a low-privilege user or container so a compromised server can't touch the rest of your machine.`,
        },
        evidence: [{ path: s.source.path, locator: s.source.locator, redactedSnippet: evidenceSnippet(cmdline) }],
      });
    }
  }
  return findings;
};
