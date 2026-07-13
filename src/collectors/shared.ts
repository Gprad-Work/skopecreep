/** Helpers for building ContextSource and CredentialAtRest entries. */
import type { ContextRole, ContextSource, CredentialAtRest, ToolId } from "../model.js";
import { looksLikeSecret, type SecretMatch, scanTextForSecrets } from "../secrets/patterns.js";
import { fingerprint } from "../secrets/redact.js";
import { isInVcsOrSyncedDir, readTextSafe, sha256, statInfo } from "../util.js";

const MAX_CONTENT_BYTES = 256 * 1024;

/** Read a text/instruction/memory file into a ContextSource (content kept in memory only). */
export function makeContextSource(tool: ToolId, role: ContextRole, filePath: string): ContextSource | null {
  const st = statInfo(filePath);
  const text = readTextSafe(filePath);
  if (text === null) return null;
  const tooBig = st !== null && st.sizeBytes > MAX_CONTENT_BYTES;
  return {
    tool,
    role,
    path: filePath,
    sha256: sha256(text),
    sizeBytes: st?.sizeBytes ?? Buffer.byteLength(text),
    content: tooBig ? "" : text,
  };
}

/** Recursively collect secret-looking values from a parsed JSON structure. */
function walkJsonForSecrets(value: unknown, acc: SecretMatch[]): void {
  if (typeof value === "string") {
    const m = looksLikeSecret(value);
    if (m.isSecret) acc.push(m);
  } else if (Array.isArray(value)) {
    for (const v of value) walkJsonForSecrets(v, acc);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) walkJsonForSecrets(v, acc);
  }
}

/**
 * Scan a file that may hold credentials (e.g. `~/.codex/auth.json`). Returns a
 * CredentialAtRest if any secret-shaped value is present. Never stores values.
 */
export function collectCredentialFromFile(tool: ToolId, filePath: string): CredentialAtRest | null {
  const text = readTextSafe(filePath);
  if (text === null) return null;

  const matches = scanTextForSecrets(text);
  // Also look inside parsed JSON values (catches opaque high-entropy tokens
  // that aren't a known signature).
  try {
    walkJsonForSecrets(JSON.parse(text), matches);
  } catch {
    /* not JSON — signature scan above still applies */
  }
  if (matches.length === 0) return null;

  // Prefer the most alarming kind for labeling.
  const priority = ["private-key", "jwt", "aws-access-key", "openai-key", "anthropic-key"];
  matches.sort((a, b) => {
    const ra = priority.indexOf(a.kind);
    const rb = priority.indexOf(b.kind);
    return (ra === -1 ? 99 : ra) - (rb === -1 ? 99 : rb);
  });
  const primary = matches[0]!;
  const kind = primary.kind === "jwt" ? "oauth-token" : primary.kind;

  const st = statInfo(filePath);
  return {
    tool,
    path: filePath,
    kind,
    perms: st?.perms ?? "unknown",
    worldOrGroupReadable: st?.worldOrGroupReadable ?? false,
    inVcsOrSyncedDir: isInVcsOrSyncedDir(filePath),
    redactedFingerprint: fingerprint(primary),
    source: { path: filePath },
  };
}
