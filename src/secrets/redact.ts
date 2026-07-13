/**
 * Redaction layer. HARD INVARIANT: nothing produced here ever contains a raw
 * secret value. Fingerprints expose only type, length, entropy, and (when the
 * value is long enough to be non-identifying) the last four characters.
 */
import { type SecretMatch, SIGNATURES, shannonEntropy } from "./patterns.js";

/** e.g. `jwt ****a1b2 (len 812, entropy 5.4)` */
export function fingerprint(match: SecretMatch): string {
  const v = match.matched;
  const last4 = v.length >= 12 ? v.slice(-4) : ""; // don't reveal tails of short secrets
  const tail = last4 ? ` ****${last4}` : " ****";
  return `${match.kind}${tail} (len ${v.length}, entropy ${match.entropy.toFixed(1)})`;
}

/** A compact inline redaction token safe to place in evidence snippets. */
export function redactionToken(match: SecretMatch): string {
  const v = match.matched;
  const last4 = v.length >= 12 ? v.slice(-4) : "";
  return `‹redacted:${match.kind}${last4 ? ` ****${last4}` : ""}›`;
}

/**
 * Replace every signature match in free text with a redaction token. Use this
 * on ANY snippet before it enters a Finding, a log line, or a report.
 */
export function redactSecretsInText(text: string): string {
  let out = text;
  for (const sig of SIGNATURES) {
    const re = new RegExp(sig.regex.source, "g");
    out = out.replace(re, (m) => {
      const last4 = m.length >= 12 ? m.slice(-4) : "";
      return `‹redacted:${sig.kind}${last4 ? ` ****${last4}` : ""}›`;
    });
  }
  return out;
}

/**
 * Build a redacted, single-line evidence snippet from a source line, trimming
 * to a sane length. Always runs redaction.
 */
export function evidenceSnippet(line: string, maxLen = 160): string {
  const redacted = redactSecretsInText(line.trim());
  return redacted.length > maxLen ? `${redacted.slice(0, maxLen)}…` : redacted;
}

/**
 * Test/self-check guard: throw if any of the given raw secret values appears in
 * `output`. Powers `skopecreep redact-check` and the redaction-leak test.
 */
export function assertNoSecretLeak(output: string, rawSecrets: string[]): void {
  for (const s of rawSecrets) {
    if (s.length >= 6 && output.includes(s)) {
      throw new Error(`Secret leak detected: a raw secret value appeared in output (len ${s.length}).`);
    }
  }
}

/** Convenience: is this string obviously a private key body we must never print? */
export function isPrivateKeyBlob(text: string): boolean {
  return /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/.test(text);
}

export { shannonEntropy };
