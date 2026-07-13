/**
 * The "never touches the network" guarantee, enforced as a build-failing
 * invariant rather than a README claim: no file in the shipped output may
 * import a network-capable Node module or call fetch/XHR/WebSocket.
 *
 * URLs are allowed as *strings* (ATLAS links, remediation text) — this test
 * targets capabilities, not content.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const distDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist");

const NETWORK_MODULES = ["node:http", "node:https", "node:net", "node:tls", "node:dgram", "node:dns", "node:http2"];
// Bare specifiers (without the node: prefix) — same modules.
const BARE_NETWORK_MODULES = NETWORK_MODULES.map((m) => m.slice("node:".length));

function importsOf(source: string): string[] {
  const specs: string[] = [];
  for (const m of source.matchAll(/(?:from\s*|import\s*\(\s*|require\s*\(\s*)["']([^"']+)["']/g)) {
    specs.push(m[1]!);
  }
  return specs;
}

function walkJs(dir: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walkJs(full));
    else if (e.isFile() && e.name.endsWith(".js")) out.push(full);
  }
  return out;
}

describe("no-network invariant", () => {
  const files = walkJs(distDir);

  it("finds the built output (guards against a silently-empty dist)", () => {
    expect(files.length).toBeGreaterThan(10);
  });

  it("no shipped file imports a network-capable module", () => {
    for (const f of files) {
      const src = fs.readFileSync(f, "utf8");
      for (const spec of importsOf(src)) {
        expect(
          NETWORK_MODULES.includes(spec) || BARE_NETWORK_MODULES.includes(spec),
          `${path.relative(distDir, f)} imports network module "${spec}"`,
        ).toBe(false);
      }
    }
  });

  it("no shipped file calls fetch, XMLHttpRequest, or WebSocket", () => {
    for (const f of files) {
      const src = fs.readFileSync(f, "utf8");
      expect(/\bfetch\s*\(/.test(src), `${path.relative(distDir, f)} calls fetch()`).toBe(false);
      expect(/\bXMLHttpRequest\b/.test(src), `${path.relative(distDir, f)} uses XMLHttpRequest`).toBe(false);
      expect(/\bnew\s+WebSocket\b/.test(src), `${path.relative(distDir, f)} opens a WebSocket`).toBe(false);
    }
  });

  it("runtime dependencies are exactly the four vetted parsers/formatters", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(distDir, "..", "package.json"), "utf8"));
    expect(Object.keys(pkg.dependencies).sort()).toEqual(["jsonc-parser", "picocolors", "smol-toml", "yaml"]);
  });
});
