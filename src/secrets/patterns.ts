/** Secret signatures + entropy heuristics. Detection only — never emits values. */

export interface SecretSignature {
  kind: string;
  label: string;
  regex: RegExp;
}

/**
 * Ordered: more specific signatures first (e.g. Anthropic `sk-ant-` before the
 * generic OpenAI `sk-`). `looksLikeSecret` returns the first match.
 */
export const SIGNATURES: SecretSignature[] = [
  { kind: "anthropic-key", label: "Anthropic API key", regex: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { kind: "openai-key", label: "OpenAI API key", regex: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/ },
  { kind: "github-token", label: "GitHub token", regex: /gh[pousr]_[A-Za-z0-9]{30,}/ },
  { kind: "aws-access-key", label: "AWS access key id", regex: /AKIA[0-9A-Z]{16}/ },
  { kind: "google-api-key", label: "Google API key", regex: /AIza[0-9A-Za-z_-]{35}/ },
  { kind: "slack-token", label: "Slack token", regex: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { kind: "jwt", label: "JWT", regex: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/ },
  {
    kind: "private-key",
    label: "PEM private key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
  },
];

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const PURE_HEX_RE = /^[0-9a-fA-F]+$/;

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

export interface SecretMatch {
  isSecret: boolean;
  kind: string;
  label: string;
  entropy: number;
  /** the specific matched substring (for redaction fingerprinting only) */
  matched: string;
}

const NOT_SECRET: SecretMatch = {
  isSecret: false,
  kind: "",
  label: "",
  entropy: 0,
  matched: "",
};

/**
 * Classify a single config/env VALUE. Signatures fire regardless of length;
 * the generic entropy path is deliberately conservative to avoid flagging
 * UUIDs, hashes, paths, and ordinary config strings.
 */
export function looksLikeSecret(value: unknown): SecretMatch {
  if (typeof value !== "string") return NOT_SECRET;
  const v = value.trim();
  if (v.length === 0) return NOT_SECRET;

  for (const sig of SIGNATURES) {
    const m = sig.regex.exec(v);
    if (m) {
      return {
        isSecret: true,
        kind: sig.kind,
        label: sig.label,
        entropy: shannonEntropy(m[0]),
        matched: m[0],
      };
    }
  }

  // Generic high-entropy fallback — intentionally narrow.
  if (UUID_RE.test(v)) return NOT_SECRET; // e.g. a Jira cloudId is not a secret
  if (v.length < 24) return NOT_SECRET;
  if (/\s/.test(v) || v.includes("/")) return NOT_SECRET; // prose / paths / URLs
  if (PURE_HEX_RE.test(v) && [32, 40, 64].includes(v.length)) return NOT_SECRET; // digests
  const hasLetter = /[A-Za-z]/.test(v);
  const hasDigit = /[0-9]/.test(v);
  const entropy = shannonEntropy(v);
  if (hasLetter && hasDigit && entropy >= 4.0) {
    return { isSecret: true, kind: "high-entropy", label: "high-entropy secret", entropy, matched: v };
  }
  return NOT_SECRET;
}

/** Scan free text for signature matches only (no entropy pass — too noisy for prose). */
export function scanTextForSecrets(text: string): SecretMatch[] {
  const found: SecretMatch[] = [];
  for (const sig of SIGNATURES) {
    const re = new RegExp(sig.regex.source, "g");
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: standard exec-loop idiom for global regexes
    while ((m = re.exec(text)) !== null) {
      found.push({
        isSecret: true,
        kind: sig.kind,
        label: sig.label,
        entropy: shannonEntropy(m[0]),
        matched: m[0],
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return found;
}
