# Contributing

`skopecreep` is built so that adding coverage is small and mechanical:

> **1 collector = 1 tool. 1 detector = 1 check.**

Collectors and detectors never know about each other — collectors normalize a
tool's on-disk config into the shared `Inventory` shape (`src/model.ts`);
detectors read only that shape and emit `Finding`s. That decoupling is what
makes both easy to add in isolation, and it's the easiest way to contribute
without needing to understand the whole codebase.

## Setup

```bash
git clone https://github.com/Gprad-Work/skopecreep.git
cd skopecreep
npm install
npm run build
npm test
```

## Adding a collector (support a new tool)

1. Create `src/collectors/<tool>.ts` following the shape of an existing one
   (`src/collectors/copilot.ts` is the smallest example to start from).
2. Read the tool's config file(s) read-only and push normalized entries onto
   the `Inventory`: `tools`, `mcpServers`, `grants`, `hooks`, `contextSources`,
   `credentials`, `capabilityDefs` — whichever apply. Never store secret
   values themselves; only fingerprints (see `src/secrets/`).
3. Register the collector in `src/collectors/index.ts`.
4. Add the tool id to `ToolId` / `ALL_TOOL_IDS` in `src/model.ts` if it's new.
5. Add a fixture-based test following the pattern in `test/audit.test.ts`
   (write a temp fixture dir, run `runAudit`, assert on `report.findings`).

Good first candidates: `gemini-cli`, `aider`, `continue`, `zed`, `opencode`.

## Adding a detector (add a new check)

1. Create `src/detectors/<check>.ts` exporting a `Detector` — a pure function
   `(inv: Inventory) => Finding[]` (see `src/detectors/types.ts`).
2. Register it in `src/detectors/index.ts`.
3. Compute severity via `computeSeverity({ impact, exposure, exploitability })`
   from `src/severity.ts` — never hardcode a severity label. Calibration is
   the whole point of the tool: a zero-impact observation must never be able
   to escalate into a scary finding.
4. Add a unit test under `test/detectors/<check>.test.ts` using the fixture
   helpers in `test/detectors/helpers.ts` (build a minimal `Inventory`
   directly — no filesystem needed for detector tests).

## Guidelines

- **Never print a secret value.** Route anything secret-shaped through
  `src/secrets/redact.ts`. Run `skopecreep redact-check` and keep the "never
  leaks a secret" test in `test/audit.test.ts` green.
- **Read-only.** Collectors must never write to a tool's config or any other
  file outside the scan.
- **No false-positive noise.** If you're unsure whether something deserves a
  finding, prefer a lower `impact`/`exposure` over skipping severity
  calibration entirely.
- Run `npm run typecheck` and `npm test` before opening a PR.

## Pull requests

Keep PRs scoped to one collector or one detector where possible — small PRs
are also easier to review for the redaction/read-only invariants above.
