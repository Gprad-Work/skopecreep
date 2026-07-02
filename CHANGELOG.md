# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Collectors for Claude Code, Codex CLI, Cursor, Windsurf, GitHub Copilot, and
  generic `AGENTS.md` / `.mcp.json` setups
- 18 detection rules covering permissions, lifecycle hooks, trusted
  directories/sandboxing, plaintext secrets at rest and in MCP env blocks,
  context-injection/hidden-Unicode, and MCP supply-chain risk
- Calibrated severity model: `risk = impact × (exposure + exploitability)`
- Terminal, JSON, and self-contained HTML reporters
- Secret fingerprinting and `redact-check` self-test — never prints a raw
  secret value
- Baseline support and `--fail-on` for CI gating
- GitHub Actions CI matrix (Node 20/22/24 × ubuntu/macos/windows)
- Per-detector unit test suite alongside the integration fixture suite

### Notes
- `skopecreep@0.0.1` is a bare name-reservation placeholder on npm — it is
  not this codebase. The first real release will be `0.1.0`.
