# skopecreep

[![CI](https://github.com/Gprad-Work/skopecreep/actions/workflows/ci.yml/badge.svg)](https://github.com/Gprad-Work/skopecreep/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/skopecreep.svg)](https://www.npmjs.com/package/skopecreep)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

> Catch the scope creep in your AI coding agents — audit what they're actually allowed to do, and what they've been told.

`skopecreep` inventories the configuration and granted scope of the AI coding
agents on your machine (Claude Code, OpenAI Codex CLI, Cursor, Windsurf, GitHub
Copilot, and generic `AGENTS.md` / `.mcp.json`) and flags risky configuration:
MCP servers that auto-execute code, over-broad permission and trust grants,
lifecycle hooks, plaintext credentials on disk, and instruction/memory files
that silently steer the agent (a prompt-injection surface).

It is **read-only**, runs locally, and **never prints a secret value**.

```
npx skopecreep
```

## Sample output

Real terminal output from a scan of a machine with a plaintext credential, an
unscoped `Bash(*)` permission, a `bypassPermissions` default, a weakened Codex
sandbox, and an MCP server pulling an unpinned package — abbreviated here to
the summary and top findings (a full run also reports lower-severity items):

```
skopecreep — AI tooling scope audit
scanned 2026-07-01T22:58:21.903Z · platform darwin

Tools
  ✓ Claude Code                      0 MCP · 2 grants · 0 hooks · 1 context · 0 creds
  ✓ OpenAI Codex CLI                 1 MCP · 2 grants · 0 hooks · 0 context · 1 creds
  ✗ Cursor                           not installed
  ✗ Windsurf / Codeium               not installed
  ✗ GitHub Copilot                   not installed
  ✓ Generic (AGENTS.md / .mcp.json)  0 MCP · 0 grants · 0 hooks · 0 context · 0 creds

Findings 1 critical · 4 high · 2 medium

 CRITICAL  Plaintext aws-access-key stored on disk
  codex · secret-at-rest · confidence high
  ~/.codex/auth.json holds a aws-access-key in plaintext (aws-access-key ****MPLE (len 20, entropy 3.7)). File perms: 644. Anyone able to read this file inherits the associated access.
  ↳ ~/.codex/auth.json
      aws-access-key ****MPLE (len 20, entropy 3.7)
  fix: Rotate the credential, keep the file owner-only (chmod 600), and prefer an OS keychain or secret manager over a plaintext file. If it is in a git repo or cloud-synced folder, purge and rotate immediately.

 HIGH  Broad auto-allow permission: Bash(*)
  claude-code · broad-permission · confidence high
  An "allow" rule "Bash(*)" grants the Bash capability with no scoping (~/.claude/settings.json). A prompt-injection or a mistaken step can then use it without a confirmation gate.
  ↳ ~/.claude/settings.json (permissions.allow)
      allow: Bash(*)
  fix: Scope the rule to specific commands/paths (e.g. Bash(git status:*) instead of Bash(*)), or move it to "ask".

 HIGH  Sandbox weakened: danger-full-access
  codex · weak-sandbox · confidence high
  Sandbox mode "danger-full-access" (~/.codex/config.toml) lets the agent read/write outside a confined workspace and reach the full filesystem/network, so any tool call — including injected ones — runs with your full user privileges.
  ↳ ~/.codex/config.toml (sandbox_mode)
      danger-full-access
  fix: Use a confined sandbox (e.g. workspace-write / read-only) unless you explicitly need full access for a single task.

 MEDIUM  MCP server "snyk" auto-installs an unpinned package (snyk@latest)
  codex · mcp-unpinned-package · confidence high
  "snyk" runs `npx -y snyk@latest mcp`, which resolves "snyk@latest" fresh from a public registry on every launch. An unpinned dependency means a compromised, hijacked, or typosquatted release would execute with your privileges inside the agent.
  ↳ ~/.codex/config.toml (mcpServers.snyk)
      npx -y snyk@latest mcp
  fix: Pin the package to an exact version (and ideally a lockfile/integrity hash) instead of "@latest" or a bare name.
```

The same scan with `--format html --out report.html` produces a shareable,
self-contained dossier version of this report with the same findings and
fixes, groupable by tool or severity.

> A recorded terminal GIF and an HTML-report screenshot are planned for this
> section — text output above is real tool output, not mocked up.

## Install

```bash
# one-off, no install
npx skopecreep

# or install globally
npm install -g skopecreep
skopecreep

# CI: fail the build on high/critical findings
npx skopecreep scan --fail-on high
```

Requires Node.js >= 20. `skopecreep` only reads local files — it never sends
anything over the network.

## skopecreep vs mcp-scan

They audit different sides of the same problem and are meant to be used
together, not as alternatives:

| | [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) | skopecreep |
| --- | --- | --- |
| Audits | The MCP **servers** you connect to (tool poisoning, rug pulls, cross-server injection) | **Your machine's** granted scope across every coding agent (permissions, hooks, trust, secrets, context injection) |
| Scope | MCP protocol specifically | Claude Code, Codex CLI, Cursor, Windsurf, Copilot, and generic `AGENTS.md`/`.mcp.json` — MCP is one part of it |
| Question it answers | "Is this MCP server safe to connect to?" | "What have I actually granted my agents, and where does it stand out as risky?" |
| Output | Server-side risk findings | Calibrated findings ranked by `risk = impact × (exposure + exploitability)`, with baselining and `--fail-on` for CI |

If you connect to third-party MCP servers, run mcp-scan on those servers and
skopecreep on your own machine's configuration — they don't overlap.

## Why

Every AI coding tool accumulates an invisible attack surface: an MCP server that
runs `npx -y something@latest` on launch, a `bypassPermissions` default, a
broadly "trusted" parent directory, an OAuth token sitting in a plaintext
`auth.json`, or a `CLAUDE.md` that quietly tells the agent to fetch and run an
external file. `skopecreep` puts all of it in one report — ranked, explained,
and with a concrete fix.

The design goal is **calibration, not noise**. Severity is computed as
`risk = impact × (exposure + exploitability)`, so a zero-impact observation (a
non-secret UUID, a first-party SaaS MCP host) can never be escalated into a
scary finding, and the *same* secret is rated `medium` at `600` perms in your
home dir but `critical` once it lands in a git repo or a synced folder.

## Usage

```bash
skopecreep                          # scan everything, human-readable report
skopecreep scan --tool codex,cursor # limit to specific tools
skopecreep scan --format json --out report.json
skopecreep scan --format html --out report.html   # shareable dossier-style report
skopecreep scan --min-severity medium
skopecreep scan --fail-on high      # non-zero exit for CI gating
skopecreep scan --baseline .skopecreep-baseline.json
skopecreep list-mcp                 # quick MCP-server inventory across tools
skopecreep redact-check             # self-test: assert no secret leaks into output
```

Options:

| Flag | Meaning |
| --- | --- |
| `--tool <a,b>` | Limit to `claude`, `codex`, `cursor`, `windsurf`, `copilot`, `generic` |
| `--path <dir>` | Project dir to scan for project-scoped config (default: cwd) |
| `--format <fmt>` | `terminal` (default), `json`, or `html` (self-contained report) |
| `--out <file>` | Write the report to a file instead of stdout |
| `--min-severity <s>` | `info` \| `low` \| `medium` \| `high` \| `critical` (default `low`) |
| `--baseline <file>` | Suppress findings whose id is listed in this JSON file |
| `--fail-on <s>` | Exit non-zero if any kept finding is at/above this severity |

### Baselines

Accept known findings so repeat runs stay quiet. A baseline is JSON — either an
array of finding ids or `{ "ignore": ["<id>", …] }`. Finding ids are stable
across runs, so a triaged finding stays suppressed until the underlying config
changes.

## What it checks

| Rule | What it flags |
| --- | --- |
| `secret-at-rest` | Plaintext credentials in config files (e.g. Codex `auth.json`) |
| `secret-in-mcp-env` | Secret-looking values in an MCP server's `env` block |
| `secret-in-context` | Secrets embedded in instruction/memory files |
| `mcp-unpinned-package` | MCP servers that auto-install unpinned packages (`@latest`) |
| `mcp-shell-server` | MCP servers launched through a shell |
| `mcp-unknown-remote-host` | Remote MCP servers on unrecognized hosts |
| `broad-permission` | Un-scoped auto-allow rules (`Bash(*)`, etc.) |
| `permission-bypass-mode` | `bypassPermissions` / `acceptEdits` defaults |
| `auto-approve` | Auto-run / YOLO / never-prompt settings |
| `broad-trusted-dir` | A broad parent directory marked "trusted" |
| `weak-sandbox` | Sandboxing disabled / `danger-full-access` |
| `broad-cmd-allowlist` | Shell commands auto-allowed without confirmation |
| `lifecycle-hook` | Hooks that auto-run commands (escalated if network/obfuscated) |
| `context-injection` | Prompt-injection language in instruction/memory files |
| `context-hidden-unicode` | Hidden / bidirectional Unicode (Trojan Source) in context |
| `context-base64-blob` | Large embedded base64 payloads in context |
| `context-external-dep` | Instructions that depend on an external file |
| `world-writable-config` | Agent config writable by other local users |

## Safety

- **Read-only.** It never writes to, or modifies, any tool's configuration.
- **Never leaks secrets.** Detected secrets are only ever reported as a
  fingerprint (`kind`, length, entropy, last-4). The `redact-check` command
  re-renders the full report and asserts no secret-shaped value survives into
  output; a unit test enforces the same invariant.
- **Privacy.** v1 audits configuration only — it does not read conversation
  transcripts. Context/instruction files are read into memory for scanning and
  their bodies are never written to any report.

## Development

```bash
npm install
npm run build      # tsc -> dist/
npm test           # build + vitest
npm run dev -- scan   # run from source via tsx
```

Architecture: `collectors → normalized model → detectors → severity → baseline
→ reporters`. Detectors operate only on the normalized model, so adding a tool
is one collector and adding a check is one detector. See `src/model.ts`.

## Roadmap

- Call-history analysis (Codex SQLite logs, Claude transcripts) — report which
  tools/MCP calls were actually made, not just what's configured.
- SARIF output + a GitHub Action.
- Live MCP OAuth **scope** introspection.
- More tools (aider, continue, gemini, zed).
- Single static binary distribution (Go) for a runtime-free install.

## License

[MIT](./LICENSE). The CLI and all detectors are free forever — a possible
future hosted/fleet tier would live in a separate package, not behind a
paywall here.
