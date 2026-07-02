**What this changes**

**Which of the two it is** (per `CONTRIBUTING.md` — "1 collector = 1 tool, 1
detector = 1 check"):
- [ ] New/updated collector
- [ ] New/updated detector
- [ ] Reporter / CLI change
- [ ] Docs / tests only
- [ ] Something else

**Checklist**
- [ ] `npm run typecheck` passes
- [ ] `npm test` passes
- [ ] If this touches findings/output: `skopecreep redact-check` still passes
      — no secret value (only a redacted fingerprint) reaches any output
- [ ] If this adds a collector or detector: added a fixture-based test
      (`test/audit.test.ts` pattern for collectors, `test/detectors/*.test.ts`
      pattern for detectors)
- [ ] Collectors are still read-only — nothing here writes to a tool's config
      or any file outside the scan
