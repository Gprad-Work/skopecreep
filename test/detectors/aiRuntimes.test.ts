import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { detectAiRuntimes } from "../../dist/detectors/aiRuntimes.js";
import type { AIRuntime } from "../../dist/model.js";
import { inv } from "./helpers.js";

function runtime(over: Partial<AIRuntime>): AIRuntime {
  return { id: "huggingface", displayName: "Hugging Face", kind: "model-hub", installed: true, evidence: [], ...over };
}

describe("detectAiRuntimes", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "skopecreep-airt-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("flags a plaintext token file at rest and never prints its value", () => {
    const tokenFile = path.join(dir, "token");
    const secret = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab";
    fs.writeFileSync(tokenFile, `${secret}\n`);
    const findings = detectAiRuntimes(inv({ aiRuntimes: [runtime({ tokenFiles: [tokenFile] })] }));
    const f = findings.find((x) => x.ruleId === "ai-runtime-token-at-rest");
    expect(f).toBeDefined();
    expect(JSON.stringify(f)).not.toContain(secret); // fingerprint only
  });

  it("does not flag an empty or missing token file", () => {
    const empty = path.join(dir, "empty");
    fs.writeFileSync(empty, "  \n");
    expect(
      detectAiRuntimes(inv({ aiRuntimes: [runtime({ tokenFiles: [empty, path.join(dir, "nope")] })] })),
    ).toHaveLength(0);
  });

  it("flags a local runtime bound to a non-loopback address", () => {
    const findings = detectAiRuntimes(
      inv({
        aiRuntimes: [runtime({ id: "ollama", displayName: "Ollama", kind: "local-runtime", exposedHost: "0.0.0.0" })],
      }),
    );
    const f = findings.find((x) => x.ruleId === "ai-runtime-exposed");
    expect(f).toBeDefined();
    expect(f?.title).toContain("0.0.0.0");
  });

  it("emits nothing for a recognized runtime with no risk signals (presence is inventory only)", () => {
    expect(detectAiRuntimes(inv({ aiRuntimes: [runtime({ evidence: ["/home/u/.cache/huggingface"] })] }))).toHaveLength(
      0,
    );
  });
});
