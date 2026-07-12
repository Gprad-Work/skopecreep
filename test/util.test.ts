import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { expandHome, readTextSafe, isInVcsOrSyncedDir, walk } from "../dist/util.js";

describe("expandHome - path traversal protection", () => {
  it("expands ~ to home directory", () => {
    const result = expandHome("~");
    expect(result).toBe(os.homedir());
  });

  it("expands ~/subdir to home/subdir", () => {
    const result = expandHome("~/Documents");
    expect(result).toBe(path.join(os.homedir(), "Documents"));
  });

  it("returns non-tilde paths unchanged", () => {
    const result = expandHome("/absolute/path");
    expect(result).toBe("/absolute/path");
  });

  it("rejects path traversal with .. in tilde expansion", () => {
    expect(() => expandHome("~/../etc/passwd")).toThrow("Invalid path");
    expect(() => expandHome("~/subdir/../../../etc/passwd")).toThrow("Invalid path");
    expect(() => expandHome("~/../../root")).toThrow("Invalid path");
  });

  it("rejects absolute paths in tilde expansion", () => {
    expect(() => expandHome("~//etc/passwd")).toThrow("Invalid path");
    expect(() => expandHome("~/./../../etc/passwd")).toThrow("Invalid path");
  });
});

describe("readTextSafe - path traversal protection", () => {
  let tmpDir: string;
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "util-test-"));
    process.chdir(tmpDir);
    fs.writeFileSync(path.join(tmpDir, "safe.txt"), "safe content");
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("reads a safe relative path", () => {
    const content = readTextSafe("safe.txt");
    expect(content).toBe("safe content");
  });

  it("rejects paths with .. traversal", () => {
    const result = readTextSafe("../../../etc/passwd");
    expect(result).toBeNull();
  });

  it("rejects absolute paths", () => {
    const result = readTextSafe("/etc/passwd");
    expect(result).toBeNull();
  });

  it("rejects paths with embedded .. segments", () => {
    const result = readTextSafe("subdir/../../../etc/passwd");
    expect(result).toBeNull();
  });

  it("returns null for non-existent files", () => {
    const result = readTextSafe("nonexistent.txt");
    expect(result).toBeNull();
  });
});

describe("isInVcsOrSyncedDir - path traversal protection", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vcs-test-"));
    process.chdir(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns false for a regular file in cwd", () => {
    const testFile = path.join(tmpDir, "test.txt");
    fs.writeFileSync(testFile, "content");
    expect(isInVcsOrSyncedDir(testFile)).toBe(false);
  });

  it("returns true for a file in a .git directory", () => {
    const gitDir = path.join(tmpDir, ".git");
    fs.mkdirSync(gitDir);
    const testFile = path.join(tmpDir, "test.txt");
    fs.writeFileSync(testFile, "content");
    expect(isInVcsOrSyncedDir(testFile)).toBe(true);
  });

  it("throws on path traversal attempts with ..", () => {
    // Create a file outside tmpDir
    const outsideDir = path.join(os.tmpdir(), "outside-test");
    fs.mkdirSync(outsideDir, { recursive: true });
    const outsideFile = path.join(outsideDir, "outside.txt");
    fs.writeFileSync(outsideFile, "outside");

    try {
      // Attempt to check a file outside the current working directory
      expect(() => isInVcsOrSyncedDir(outsideFile)).toThrow("Invalid path");
    } finally {
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });
});

describe("walk - path traversal protection", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "walk-test-"));
    // Create a safe directory structure
    fs.mkdirSync(path.join(tmpDir, "subdir"));
    fs.writeFileSync(path.join(tmpDir, "file1.txt"), "content1");
    fs.writeFileSync(path.join(tmpDir, "subdir", "file2.txt"), "content2");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("walks a safe directory structure", () => {
    const files = walk(tmpDir, {
      maxDepth: 5,
      skipDirs: new Set(),
      match: (name) => name.endsWith(".txt"),
    });
    expect(files.length).toBe(2);
    expect(files.some((f) => f.endsWith("file1.txt"))).toBe(true);
    expect(files.some((f) => f.endsWith("file2.txt"))).toBe(true);
  });

  it("skips directories with names in skipDirs", () => {
    const files = walk(tmpDir, {
      maxDepth: 5,
      skipDirs: new Set(["subdir"]),
      match: (name) => name.endsWith(".txt"),
    });
    expect(files.length).toBe(1);
    expect(files[0]).toContain("file1.txt");
  });

  it("prevents traversal outside root via symlinks", () => {
    if (process.platform === "win32") return; // Skip on Windows (symlink behavior differs)

    // Create a symlink that points outside the root
    const outsideDir = path.join(os.tmpdir(), "outside-walk");
    fs.mkdirSync(outsideDir, { recursive: true });
    fs.writeFileSync(path.join(outsideDir, "outside.txt"), "outside");

    const symlinkPath = path.join(tmpDir, "escape");
    try {
      fs.symlinkSync(outsideDir, symlinkPath);

      const files = walk(tmpDir, {
        maxDepth: 5,
        skipDirs: new Set(),
        match: (name) => name.endsWith(".txt"),
      });

      // The walk function should not include files from outside the root
      const outsideFiles = files.filter((f) => f.includes("outside.txt"));
      expect(outsideFiles.length).toBe(0);
    } finally {
      fs.rmSync(outsideDir, { recursive: true, force: true });
      if (fs.existsSync(symlinkPath)) {
        fs.unlinkSync(symlinkPath);
      }
    }
  });

  it("respects maxDepth limit", () => {
    // Create a deeper structure
    fs.mkdirSync(path.join(tmpDir, "subdir", "deep"));
    fs.writeFileSync(path.join(tmpDir, "subdir", "deep", "file3.txt"), "content3");

    const files = walk(tmpDir, {
      maxDepth: 1,
      skipDirs: new Set(),
      match: (name) => name.endsWith(".txt"),
    });

    // Should only find files at depth 0 and 1
    expect(files.length).toBe(2);
    expect(files.some((f) => f.endsWith("file3.txt"))).toBe(false);
  });
});
