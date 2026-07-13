# skopecreep

[![CI](https://github.com/Gprad-Work/skopecreep/actions/workflows/ci.yml/badge.svg)](https://github.com/Gprad-Work/skopecreep/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/skopecreep)](https://www.npmjs.com/package/skopecreep)
[![node](https://img.shields.io/node/v/skopecreep)](https://www.npmjs.com/package/skopecreep)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A read-only CLI that audits the configuration and granted scope of your AI
coding agents — Claude Code, Codex CLI, Cursor, Windsurf, Copilot, and generic
`AGENTS.md`/`.mcp.json` setups — flagging auto-executing MCP servers,
over-broad permissions, lifecycle hooks, plaintext secrets, and
prompt-injection surface in context files. Runs locally, never prints a
secret value.

```
npx skopecreep
```

## Contents

- [Install](#install)
- [Usage](#usage)
- [What it checks](#what-it-checks)
- [Why](#why)
- [skopecreep vs mcp-scan](#skopecreep-vs-mcp-scan)
- [Safety](#safety)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

See [docs/sample-output.md](docs/sample-output.md) for a real terminal run
against a machine with several findings.

## Install

```bash
# one-off, no install (recommended for a first look)
npx skopecreep

# or install globally for repeated use
npm install -g skopecreep
skopecreep

# CI: fail the build on high/critical findings
npx skopecreep scan --fail-on high
```

Requires Node.js >= 20. `skopecreep` only reads local files — it never sends
anything over the network.

## Usage

```bash
skopecreep                          # scan everything, human-readable report
skopecreep scan --tool codex,cursor # limit to specific tools
skopecreep scan --format json --out report.json
skopecreep scan --format html --out report.html   # shareable dossier-style report
skopecreep scan --format sarif --out skopecreep.sarif   # GitHub code scanning
skopecreep scan --min-severity medium
skopecreep scan --fail-on high      # non-zero exit for CI gating
skopecreep scan --write-baseline .skopecreep-baseline.json   # accept current findings
skopecreep scan --baseline .skopecreep-baseline.json         # …and stay quiet about them
skopecreep scan --verbose           # also list the config files scanned per tool
skopecreep list-mcp                 # quick MCP-server inventory across tools
skopecreep redact-check             # self-test: assert no secret leaks into output
```

Options:

| Flag | Meaning |
| --- | --- |
| `--tool <a,b>` | Limit to `claude`, `codex`, `cursor`, `windsurf`, `copilot`, `generic` |
| `--path <dir>` | Project dir to scan for project-scoped config (default: cwd) |
| `--format <fmt>` | `terminal` (default), `json`, `html` (self-contained report), or `sarif` (code scanning) |
| `--out <file>` | Write the report to a file instead of stdout |
| `--min-severity <s>` | `info` \| `low` \| `medium` \| `high` \| `critical` (default `low`) |
| `--baseline <file>` | Suppress findings whose id is listed in this JSON file |
| `--write-baseline <file>` | Snapshot all current finding ids into a baseline file |
| `--fail-on <s>` | Exit non-zero if any kept finding is at/above this severity |
| `--verbose` | Also list the config files each tool's collector read |

### Baselines

Accept known findings so repeat runs stay quiet. Create one with
`--write-baseline <file>` (it snapshots every current finding id), then pass
`--baseline <file>` on subsequent runs. The file is JSON — either an array of
finding ids or `{ "ignore": ["<id>", …] }`. Finding ids are stable across
runs, so a triaged finding stays suppressed until the underlying config
changes. A baseline file that is missing or malformed is a hard error, not a
silent no-op.

### CI integration

GitHub Actions — the bundled action scans the runner + checkout and feeds
GitHub code scanning:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - id: scan
    uses: Gprad-Work/skopecreep@v0.3.0
    with:
      fail-on: "" # upload first, gate later (or set: high)
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.scan.outputs.report-file }}
```

Findings then appear in the repo's **Security → Code scanning** tab, with
severity, graded fixes, and ATLAS technique tags. To hard-gate instead, set
`fail-on: high` (exit code 1 fails the job).

Any other CI (GitLab example):

```yaml
agent-audit:
  image: node:22
  script:
    - npx --yes skopecreep@0.3.0 scan --format json --out skopecreep.json --fail-on high
  artifacts:
    paths: [skopecreep.json]
    when: always
```

### Output schema stability

JSON output carries a top-level `schemaVersion` (currently `1`), with a
machine contract in
[`schema/skopecreep-report.v1.schema.json`](schema/skopecreep-report.v1.schema.json)
that the test suite validates against. Policy: **additive** changes (new
fields, new rules) never bump `schemaVersion`; **breaking** shape changes bump
it and are called out in the CHANGELOG (the 0.2.0 change of
`finding.remediation` from string to object is the precedent this policy
exists to prevent repeating unannounced). SARIF output follows SARIF 2.1.0.

## What it checks

| Rule | What it flags |
| --- | --- |
| `secret-at-rest` | Plaintext credentials in config files (e.g. Codex `auth.json`) |
| `secret-in-mcp-env` | Secret-looking values in an MCP server's `env` block |
| `secret-in-context` | Secrets embedded in instruction/memory files |
| `mcp-unpinned-package` | MCP servers that auto-install unpinned packages (`@latest`) |
| `mcp-remote-code-source` | MCP servers that run code from a remote URL/git ref with no commit pin |
| `mcp-shell-server` | MCP servers launched through a shell |
| `mcp-unknown-remote-host` | Remote MCP servers on unrecognized hosts |
| `mcp-insecure-transport` | Remote MCP servers over plain `http://` (non-localhost) |
| `broad-permission` | Un-scoped auto-allow rules (`Bash(*)`, etc.) |
| `permission-bypass-mode` | `bypassPermissions` / `acceptEdits` defaults |
| `auto-approve` | Auto-run / YOLO / never-prompt settings |
| `broad-trusted-dir` | A broad parent directory marked "trusted" |
| `weak-sandbox` | Sandboxing disabled / `danger-full-access` |
| `broad-cmd-allowlist` | Shell commands auto-allowed without confirmation |
| `lifecycle-hook` | Hooks that auto-run commands (escalated if network/obfuscated) |
| `hook-agent-recursion` | Hooks that re-invoke a coding agent (loop / runaway-cost risk) |
| `context-injection` | Prompt-injection language in instruction/memory files |
| `context-self-replication` | Instructions that tell the agent to copy themselves into other files/repos |
| `context-system-prompt-probe` | Instructions that try to make the agent disclose its system prompt |
| `context-hidden-unicode` | Hidden / bidirectional Unicode (Trojan Source) in context |
| `context-base64-blob` | Large embedded base64 payloads in context |
| `context-external-dep` | Instructions that depend on an external file |
| `world-writable-config` | Agent config writable by other local users |

Every finding is also tagged with the [MITRE ATLAS](https://atlas.mitre.org/matrices/ATLAS)
tactic/technique it enables (e.g. `weak-sandbox` → `AML.T0053` AI Agent Tool
Invocation) — visible in the terminal, JSON, and HTML reports. See
[`src/atlas.ts`](src/atlas.ts) for the full rule → technique mapping.

Each finding ships **three graded fixes** instead of one absolute: a **loose**
fix (lowest friction — keeps your workflow, trims the risk), a **medium** fix
(the balanced default most users should apply), and a **tight** fix (maximum
lockdown). Pick your own point on the security/friction curve.

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

## Safety

- **Read-only.** It never writes to, or modifies, any tool's configuration.
- **Never leaks secrets.** Detected secrets are only ever reported as a
  fingerprint (`kind`, length, entropy, last-4). The `redact-check` command
  re-renders the full report and asserts no secret-shaped value survives into
  output; a unit test enforces the same invariant.
- **Privacy.** v1 audits configuration only — it does not read conversation
  transcripts. Context/instruction files are read into memory for scanning and
  their bodies are never written to any report.

### Don't take our word for it

Every safety claim above is enforced as a build-failing test, not a promise:

- **No network, provably.** [`test/no-network.test.ts`](test/no-network.test.ts)
  fails the build if any shipped file imports a network-capable module
  (`http`, `https`, `net`, `tls`, `dns`, …) or calls `fetch`/`WebSocket`. No
  account, no token, no telemetry — there is no code that could send anything.
- **No secret leaks, provably.** The integration suite renders a report from a
  fixture full of planted secrets through *every* output format and asserts no
  secret-shaped value survives; `skopecreep redact-check` runs the same check
  against your real machine, locally.
- **Four runtime dependencies**, each a parser or terminal-color helper —
  pinned by the same test. Small enough to read in an afternoon.

Found a security issue? See [docs/SECURITY.md](docs/SECURITY.md) —
please don't file it as a public issue.

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

Want to contribute a collector or a detector? See
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). This project follows the
[Contributor Covenant](docs/CODE_OF_CONDUCT.md).

## Roadmap

- ~~SARIF output + a GitHub Action~~ — shipped (see [CI integration](#ci-integration)).
- **Creep detection** — diff the current posture against a previous snapshot
  and flag *new* grants/servers/hooks since the last audit.
- Call-history analysis (Codex SQLite logs, Claude transcripts) — report which
  tools/MCP calls were actually made, not just what's configured.
- Live MCP OAuth **scope** introspection.
- More tools (aider, continue, gemini, zed).
- OWASP Agentic AI / MCP Top 10 mappings alongside ATLAS.
- Single static binary distribution (Go) for a runtime-free install.

## License

[MIT](./LICENSE). The CLI and all detectors are free forever — a possible
future hosted/fleet tier would live in a separate package, not behind a
paywall here. See [docs/CHANGELOG.md](docs/CHANGELOG.md) for release history.
