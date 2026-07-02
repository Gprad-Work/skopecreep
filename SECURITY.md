# Security Policy

## Reporting a Vulnerability

If you find a security issue in `skopecreep` — including a secret-leak path, a way to trigger code execution while parsing a malicious config, or a detector that's trivially bypassable — please **do not open a public GitHub issue**.

Instead, use **GitHub private vulnerability reporting** — click the "Report a vulnerability" button on the [Security tab](../../security/advisories/new) of this repo.

Please include:
- A description of the issue
- Steps to reproduce or a proof-of-concept (a minimal config fixture is ideal)
- The potential impact

You can expect an acknowledgement within 48 hours and a resolution or status update within 7 days.

## Scope

`skopecreep` is a read-only, local-only CLI. It parses configuration files (JSON/JSONC/TOML/YAML) belonging to AI coding tools, some of which may originate from a compromised or malicious cloned repo.

Security issues in scope:
- **Secret leakage** — any way a raw secret value (not a redacted fingerprint) can reach stdout, a report file, or an error message
- **Unsafe parsing** — code execution, unsafe symlink following, or scan-root escape triggered by a malicious/untrusted config file
- **Trivially bypassable detectors** — a detector that a realistic attacker-controlled config can silently evade (as opposed to an ordinary accuracy gap)
- **Supply-chain issues** in this project's own dependencies or release process

Out of scope:
- Issues in the underlying AI tools themselves (Claude Code, Codex CLI, Cursor, Windsurf, Copilot) — report those to the respective vendor
- General false positives or missing detector coverage for new attack patterns — open a regular GitHub issue for those

## Using skopecreep safely

- It's **read-only** — it never writes to, or modifies, any tool's configuration
- Detected secrets are only ever reported as a fingerprint (kind, length, entropy, last-4) — never the raw value. The `redact-check` command and a test-suite invariant both enforce this
- Only the latest version published on npm receives security fixes; there is no LTS branch at this stage
