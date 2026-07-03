---
name: Bug report
about: Something skopecreep does is wrong — a crash, a wrong finding, a missed one
title: ""
labels: bug
---

**What happened**

**What you expected instead**

**Repro**
- `skopecreep` version: <!-- `skopecreep --version` -->
- Node version:
- OS:
- Tool(s) involved (claude, codex, cursor, windsurf, copilot, generic):
- Command run:

If this is a **wrong or missing finding**, a minimal config fixture (redacted —
never paste a real secret, real path with your username, or real API key) is
the fastest way to get it fixed. See `test/audit.test.ts` for the fixture
pattern this project uses.

If this is a **security issue** (a secret leaking into output, code execution
from a malicious config, a trivially bypassable detector) — please don't file
it here. Use GitHub's private vulnerability reporting instead, see
[docs/SECURITY.md](../../docs/SECURITY.md).
