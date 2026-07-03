# Sample output

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
