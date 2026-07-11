import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { loadBaseline } from "../dist/baseline.js";

let dir: string;

function write(name: string, content: string): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  return p;
}

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "skopecreep-baseline-"));
});

afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("loadBaseline", () => {
  it("returns an empty baseline when no path is given", () => {
    expect(loadBaseline(undefined).ignore.size).toBe(0);
  });

  it("accepts a bare array of ids", () => {
    const p = write("array.json", '["aaa", "bbb"]');
    expect([...loadBaseline(p).ignore].sort()).toEqual(["aaa", "bbb"]);
  });

  it('accepts the { "ignore": [...] } shape', () => {
    const p = write("obj.json", '{ "ignore": ["ccc"] }');
    expect(loadBaseline(p).ignore.has("ccc")).toBe(true);
  });

  it("throws on a missing file instead of silently ignoring it", () => {
    expect(() => loadBaseline(path.join(dir, "nope.json"))).toThrow(/not found/);
  });

  it("throws on malformed JSON", () => {
    const p = write("bad.json", "{oops");
    expect(() => loadBaseline(p)).toThrow(/not valid JSON/);
  });

  it("throws on a wrong shape (object without ignore array)", () => {
    const p = write("shape.json", '{ "suppress": ["x"] }');
    expect(() => loadBaseline(p)).toThrow(/baseline must be/);
  });

  it("throws when the array contains non-string entries", () => {
    const p = write("mixed.json", '["ok", 42]');
    expect(() => loadBaseline(p)).toThrow(/baseline must be/);
  });
});
