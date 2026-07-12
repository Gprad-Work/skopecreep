/** Filesystem / path helpers shared by collectors. All read-only. */
import * as fs from "node:fs";
import * as path from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { parse as parseJsonc, ParseError } from "jsonc-parser";

export const HOME = homedir();
export const IS_WINDOWS = process.platform === "win32";

/** Expand a leading `~` to the user's home directory. */
export function expandHome(p: string): string {
  if (p === "~") return HOME;
  if (p.startsWith("~/")) {
    const userInput = p.slice(2);
    if (userInput.includes("..") || path.isAbsolute(userInput)) {
      throw new Error("Invalid path");
    }
    return path.join(HOME, userInput);
  }
  return p;
}

export function fileExists(p: string): boolean {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

export function isDir(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export function readTextSafe(p: string): string | null {
  try {
    if (p.includes('..') || path.isAbsolute(p)) return null;
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

export function listDir(p: string): string[] {
  try {
    return fs.readdirSync(p);
  } catch {
    return [];
  }
}

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export interface StatInfo {
  /** octal string like "600", or "unknown" on Windows */
  perms: string;
  /** true if group or other can read the file (POSIX only) */
  worldOrGroupReadable: boolean;
  /** true if group or other can write the file (POSIX only) */
  worldOrGroupWritable: boolean;
  sizeBytes: number;
}

export function statInfo(p: string): StatInfo | null {
  try {
    const st = fs.statSync(p);
    if (IS_WINDOWS) {
      // POSIX permission bits are not meaningful on Windows.
      return { perms: "unknown", worldOrGroupReadable: false, worldOrGroupWritable: false, sizeBytes: st.size };
    }
    const mode = st.mode & 0o777;
    return {
      perms: mode.toString(8).padStart(3, "0"),
      worldOrGroupReadable: (mode & 0o044) !== 0,
      worldOrGroupWritable: (mode & 0o022) !== 0,
      sizeBytes: st.size,
    };
  } catch {
    return null;
  }
}

const SYNC_DIR_MARKERS = [
  "/Library/Mobile Documents/", // iCloud Drive
  "/Dropbox/",
  "/Google Drive",
  "/My Drive/",
  "/OneDrive",
];

/**
 * True if the path lives inside a git working tree OR a known cloud-synced
 * directory — either raises the exposure of any secret found there.
 */
export function isInVcsOrSyncedDir(p: string): boolean {
  const abs = path.resolve(p);
  const relative = path.relative(process.cwd(), abs);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Invalid path');
  }
  for (const marker of SYNC_DIR_MARKERS) {
    if (abs.includes(marker)) return true;
  }
  // Walk ancestors looking for a `.git` entry, bounded to avoid runaway.
  let dir = path.dirname(abs);
  for (let i = 0; i < 40; i++) {
    if (fileExists(path.join(dir, ".git"))) return true;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

export interface WalkOpts {
  maxDepth: number;
  /** directory basenames to skip entirely */
  skipDirs: Set<string>;
  /** return true to include a file path in the result */
  match: (basename: string) => boolean;
}

/** Bounded recursive file walk — never descends into skipDirs. */
export function walk(root: string, opts: WalkOpts): string[] {
  const out: string[] = [];
  const visit = (dir: string, depth: number): void => {
    if (depth > opts.maxDepth) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      const resolvedRoot = path.resolve(root);
      const resolvedFull = path.resolve(full);
      const relative = path.relative(resolvedRoot, resolvedFull);
      if (relative.startsWith('..') || path.isAbsolute(relative)) continue;
      if (e.isDirectory()) {
        if (opts.skipDirs.has(e.name) || e.name.startsWith(".git")) continue;
        visit(resolvedFull, depth + 1);
      } else if (e.isFile() && opts.match(e.name)) {
        out.push(resolvedFull);
      }
    }
  };
  visit(root, 0);
  return out;
}

/** Parse JSON that may contain comments/trailing commas (VSCode/Cursor style). */
export function parseJsoncSafe<T = unknown>(text: string): T | null {
  const errors: ParseError[] = [];
  const result = parseJsonc(text, errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  // jsonc-parser is lenient; a few recoverable errors are fine. Bail only if
  // it produced nothing.
  if (result === undefined) return null;
  return result as T;
}

/** Parse strict JSON, returning null on failure. */
export function parseJsonSafe<T = unknown>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

/** Extract the host from a URL string, or undefined. */
export function urlHost(u: string | undefined): string | undefined {
  if (!u) return undefined;
  try {
    return new URL(u).host;
  } catch {
    return undefined;
  }
}
