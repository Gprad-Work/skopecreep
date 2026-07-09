# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Every finding is now tagged with the [MITRE ATLAS](https://atlas.mitre.org/matrices/ATLAS)
  tactic/technique it enables (e.g. `secret-at-rest` → `AML.T0055` Unsecured
  Credentials, `context-injection` → `AML.T0051.001` LLM Prompt Injection:
  Indirect). Visible in the terminal (`ATLAS:` line), JSON (`finding.atlas`),
  and HTML (linked technique tags) reporters. See `src/atlas.ts` for the full
  rule → technique mapping and `test/atlas.test.ts` for the coverage guard
  that fails CI if a new rule ships without a mapping.

## [0.1.0] - 2026-07-02

### Added
- Collectors for Claude Code, Codex CLI, Cursor, Windsurf, GitHub Copilot, and
  generic `AGENTS.md` / `.mcp.json` setups
- 18 detection rules covering permissions, lifecycle hooks, trusted
  directories/sandboxing, plaintext secrets at rest and in MCP env blocks,
  context-injection/hidden-Unicode, and MCP supply-chain risk
- Calibrated severity model: `risk = impact × (exposure + exploitability)`
- Terminal, JSON, and self-contained HTML reporters — HTML report includes a
  severity-distribution bar, severity-banded findings, and Findings/Inventory
  tabs
- Secret fingerprinting and `redact-check` self-test — never prints a raw
  secret value
- Baseline support and `--fail-on` for CI gating
- GitHub Actions CI matrix (Node 20/22/24 × ubuntu/macos/windows)
- Per-detector unit test suite covering all 9 detectors alongside the
  integration fixture suite (79 tests total)

### Notes
- `skopecreep@0.0.1`/`0.0.2` were bare name-reservation placeholders on
  npm, published ahead of this release — not this codebase.
