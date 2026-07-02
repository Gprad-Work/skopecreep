/** Shared MCP-server parsing used by several collectors. */
import * as path from "node:path";
import type { MCPServer, ToolId, SourceRef } from "../model.js";
import { looksLikeSecret } from "../secrets/patterns.js";
import { urlHost } from "../util.js";

/** Package runners whose first positional arg is the package being executed. */
const RUNNERS = new Set([
  "npx",
  "pnpx",
  "bunx",
  "uvx",
  "pipx",
  "uv",
  "npm",
  "pnpm",
  "yarn",
  "bun",
]);

const RUNNER_SKIP = new Set([
  "-y",
  "--yes",
  "run",
  "tool",
  "exec",
  "x",
  "dlx",
  "--",
  "-q",
  "--quiet",
]);

export interface PackageInfo {
  packageSpec?: string;
  pinned?: boolean;
}

/**
 * If `command` is a package runner (npx/uvx/…), figure out which package it
 * runs and whether it's pinned. Unpinned (`@latest` or no version) means the
 * next resolve could pull different code — a supply-chain concern.
 */
export function derivePackage(command: string | undefined, args: string[] | undefined): PackageInfo {
  if (!command) return {};
  const base = path.basename(command).toLowerCase();
  if (!RUNNERS.has(base)) return {};
  let spec: string | undefined;
  for (const a of args ?? []) {
    if (a.startsWith("-")) continue;
    if (RUNNER_SKIP.has(a)) continue;
    spec = a;
    break;
  }
  if (!spec) return {};
  const scoped = spec.startsWith("@");
  const body = scoped ? spec.slice(1) : spec;
  const at = body.indexOf("@");
  let pinned: boolean;
  if (at === -1) {
    pinned = false; // bare name → resolves to latest
  } else {
    const ver = body.slice(at + 1);
    pinned = ver.length > 0 && ver.toLowerCase() !== "latest";
  }
  return { packageSpec: spec, pinned };
}

interface RawMcpEntry {
  command?: string;
  args?: string[];
  url?: string;
  type?: string;
  transport?: string;
  env?: Record<string, unknown>;
}

/** Parse a `{ name: {command|url, env, …} }` map into normalized MCPServer[]. */
export function parseMcpMap(
  tool: ToolId,
  map: Record<string, RawMcpEntry> | undefined,
  sourcePath: string,
): MCPServer[] {
  if (!map || typeof map !== "object") return [];
  const servers: MCPServer[] = [];
  for (const [name, entry] of Object.entries(map)) {
    if (!entry || typeof entry !== "object") continue;
    const url = entry.url;
    const declared = (entry.type ?? entry.transport ?? "").toLowerCase();
    const transport = url ? (declared === "sse" ? "sse" : "http") : "stdio";
    const env = entry.env ?? {};
    const envKeys = Object.keys(env);
    const secretEnvKeys = envKeys.filter((k) => looksLikeSecret(env[k]).isSecret);
    const { packageSpec, pinned } = derivePackage(entry.command, entry.args);
    const source: SourceRef = { path: sourcePath, locator: `mcpServers.${name}` };
    servers.push({
      tool,
      name,
      transport,
      command: entry.command,
      args: entry.args,
      url,
      host: urlHost(url),
      envKeys,
      secretEnvKeys,
      hasSecretInEnv: secretEnvKeys.length > 0,
      packageSpec,
      pinned,
      source,
    });
  }
  return servers;
}
