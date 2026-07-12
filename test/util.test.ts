import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { expandHome, readTextSafe, isInVcsOrSyncedDir, walk } from "../dist/util.js";

describe("expandHome", () => {
  it("returns ~ as HOME", () => {
    const result = expandHome("~");
    expect(result).toBeTruthy();
    expect(result).not.toBe("~");
  });

  it("expands ~/path to HOME/path", () => {
    const result = expandHome("~/Documents");
    expect(result).toContain("Documents");
    expect(result).not.toContain("~");
  });

  it("returns non-tilde paths unchanged", () => {
    expect(expandHome("/absolute/path")).toBe("/absolute/path");
    expect(expandHome("relative/path")).toBe("relative/path");
  });

  // Path traversal security tests
  it("rejects path traversal with .. in expandHome", () => {
    expect(() => expandHome("~/../etc/passwd")).toThrow("Invalid path");
    expect(() => expandHome("~/../../etc/passwd")).toThrow("Invalid path");
    expect(() => expandHome("~/foo/../bar")).toThrow("Invalid path");
  });

  it("allows safe relative paths after tilde", () => {
    expect(() => expandHome("~/Documents/file.txt")).not.toThrow();
    expect(() => expandHome("~/foo/bar")).not.toThrow();
  });
});

describe("readTextSafe", () => {
  let tmpDir: string;
  let testFile: string;
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "util-test-"));
    process.chdir(tmpDir); // Change to temp dir so we can use relative paths
    testFile = "test.txt";
    fs.writeFileSync(testFile, "test content");
  });

  afterEach(() => {
    process.chdir(originalCwd);
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("reads a valid file", () => {
    const content = readTextSafe(testFile);
    expect(content).toBe("test content");
  });

  it("returns null for non-existent file", () => {
    const content = readTextSafe("nonexistent.txt");
    expect(content).toBeNull();
  });

  // Path traversal security tests
  it("rejects paths with .. to prevent directory traversal", () => {
    const content = readTextSafe("../etc/passwd");
    expect(content).toBeNull();
  });

  it("rejects paths with .. in the middle", () => {
    const content = readTextSafe("foo/../bar/file.txt");
    expect(content).toBeNull();
  });

  it("rejects absolute paths", () => {
    const content = readTextSafe("/etc/passwd");
    expect(content).toBeNull();
  });
});

describe("isInVcsOrSyncedDir", () => {
  it("returns false for paths with ..", () => {
    const result = isInVcsOrSyncedDir("../some/path");
    expect(result).toBe(false);
  });

  it("returns false for absolute paths", () => {
    const result = isInVcsOrSyncedDir("/absolute/path");
    expect(result).toBe(false);
  });

  it("returns false for paths with .. in the middle", () => {
    const result = isInVcsOrSyncedDir("foo/../bar");
    expect(result).toBe(false);
  });

  it("handles relative paths without traversal", () => {
    // This should not throw and should return a boolean
    const result = isInVcsOrSyncedDir("relative/path");
    expect(typeof result).toBe("boolean");
  });
});

describe("walk", () => {
  let tmpDir: string;
  let subDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "walk-test-"));
    subDir = path.join(tmpDir, "subdir");
    fs.mkdirSync(subDir);
    fs.writeFileSync(path.join(tmpDir, "file1.txt"), "content1");
    fs.writeFileSync(path.join(subDir, "file2.txt"), "content2");
  });

  afterEach(() => {
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("walks a directory and finds files", () => {
    const files = walk(tmpDir, {
      maxDepth: 5,
      skipDirs: new Set(),
      match: (name) => name.endsWith(".txt"),
    });
    expect(files.length).toBeGreaterThan(0);
  });

  it("prevents path traversal by skipping symlinks that escape root", () => {
    // Create a symlink that tries to escape
    const symlinkPath = path.join(tmpDir, "escape");
    try {
      fs.symlinkSync("..", symlinkPath);
    } catch {
      // Symlink creation might fail on some systems, skip this test
      return;
    }

    const files = walk(tmpDir, {
      maxDepth: 5,
      skipDirs: new Set(),
      match: (name) => name.endsWith(".txt"),
    });

    // All returned files should be within tmpDir
    for (const file of files) {
      const resolved = path.resolve(file);
      const relative = path.relative(tmpDir, resolved);
      expect(relative.startsWith("..")).toBe(false);
      expect(path.isAbsolute(relative)).toBe(false);
    }
  });

  it("only returns files within the root directory", () => {
    const files = walk(tmpDir, {
      maxDepth: 5,
      skipDirs: new Set(),
      match: () => true,
    });

    // Verify all files are within tmpDir
    for (const file of files) {
      const resolved = path.resolve(file);
      const relative = path.relative(tmpDir, resolved);
      expect(relative.startsWith("..")).toBe(false);
    }
  });
});

describe("path traversal security - comprehensive", () => {
  it("expandHome blocks common traversal patterns", () => {
    const traversalPatterns = [
      "~/..",
      "~/../",
      "~/../../",
      "~/../etc",
      "~/foo/..",
      "~/foo/../bar",
    ];

    for (const pattern of traversalPatterns) {
      expect(() => expandHome(pattern), `Pattern ${pattern} should be rejected`).toThrow("Invalid path");
    }
  });

  it("readTextSafe blocks common traversal patterns", () => {
    const traversalPatterns = [
      "..",
      "../",
      "../../",
      "../etc/passwd",
      "foo/..",
      "foo/../bar",
      "/etc/passwd",
      "/absolute/path",
    ];

    for (const pattern of traversalPatterns) {
      const result = readTextSafe(pattern);
      expect(result, `Pattern ${pattern} should return null`).toBeNull();
    }
  });

  it("isInVcsOrSyncedDir blocks common traversal patterns", () => {
    const traversalPatterns = [
      "..",
      "../",
      "../../",
      "../etc/passwd",
      "foo/..",
      "foo/../bar",
      "/etc/passwd",
      "/absolute/path",
    ];

    for (const pattern of traversalPatterns) {
      const result = isInVcsOrSyncedDir(pattern);
      expect(result, `Pattern ${pattern} should return false`).toBe(false);
    }
  });
});
