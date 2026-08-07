/**
 * Risk findings for recognized AI runtimes. Two deterministic rules:
 * a plaintext API/hub token at rest, and a local model runtime bound to a
 * non-loopback address (an unauthenticated inference API reachable off-host).
 * Mere presence is inventory, not a finding.
 */
import type { Finding } from "../model.js";
import { looksLikeSecret } from "../secrets/patterns.js";
import { fingerprint } from "../secrets/redact.js";
import { computeSeverity } from "../severity.js";
import { readTextSafe } from "../util.js";
import type { Detector } from "./types.js";
import { exposureForPath, makeFindingId } from "./util.js";

export const detectAiRuntimes: Detector = (inv) => {
  const findings: Finding[] = [];

  for (const rt of inv.aiRuntimes) {
    for (const tokenFile of rt.tokenFiles ?? []) {
      const raw = readTextSafe(tokenFile);
      if (raw === null || raw.trim().length === 0) continue;
      const match = looksLikeSecret(raw.trim());
      const exposure = exposureForPath(tokenFile);
      findings.push({
        id: makeFindingId("ai-runtime-token-at-rest", ["generic", tokenFile]),
        ruleId: "ai-runtime-token-at-rest",
        tool: "generic",
        severity: computeSeverity({ impact: 3, exposure, exploitability: exposure >= 3 ? 3 : 1 }),
        confidence: match.isSecret ? "high" : "medium",
        title: `${rt.displayName} API token stored in plaintext`,
        rationale:
          `${tokenFile} holds a ${rt.displayName} token in plaintext (${fingerprint(match)}). ` +
          `Anyone able to read this file inherits your ${rt.displayName} access — model downloads, private repos, or paid API spend.`,
        remediation: {
          loose: `Restrict the file to owner-only (chmod 600) and keep it out of git repos and cloud-synced folders.`,
          medium: `Move the token to an environment variable or secret manager and delete the plaintext file; rotate the token.`,
          tight: `Rotate the token, store the replacement only in a secret manager, and add secret scanning so a token can't sit in plaintext again.`,
        },
        evidence: [{ path: tokenFile, redactedSnippet: fingerprint(match) }],
      });
    }

    if (rt.exposedHost) {
      findings.push({
        id: makeFindingId("ai-runtime-exposed", ["generic", rt.id, rt.exposedHost]),
        ruleId: "ai-runtime-exposed",
        tool: "generic",
        severity: computeSeverity({ impact: 2, exposure: 2, exploitability: 2 }),
        confidence: "high",
        title: `${rt.displayName} is configured to listen on a non-loopback address (${rt.exposedHost})`,
        rationale:
          `${rt.displayName} is bound to ${rt.exposedHost}, so its inference API is reachable from the network rather than localhost-only. ` +
          `Most local runtimes ship no authentication — anyone who can reach the host can run your models, consume your GPU/CPU, and (on some runtimes) pull or delete models.`,
        remediation: {
          loose: `Confirm the exposure is intentional and the host sits on a network you fully control.`,
          medium: `Bind the runtime back to localhost (e.g. unset OLLAMA_HOST or set it to 127.0.0.1) and reach it via an SSH tunnel when you need remote access.`,
          tight: `Keep it localhost-only and put any deliberate remote access behind an authenticating reverse proxy or VPN.`,
        },
        evidence: [
          {
            path: rt.evidence[0] ?? rt.id,
            locator: rt.exposedHost,
            redactedSnippet: `${rt.displayName} → ${rt.exposedHost}`,
          },
        ],
      });
    }
  }

  return findings;
};
