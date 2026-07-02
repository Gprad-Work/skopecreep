import { describe, it, expect } from "vitest";
import { looksLikeSecret, scanTextForSecrets } from "../dist/secrets/patterns.js";
import { fingerprint, redactSecretsInText, assertNoSecretLeak } from "../dist/secrets/redact.js";

// Well-known example/fake values (not live secrets).
const AWS = "AKIAIOSFODNN7EXAMPLE";
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.s5H0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
const CLOUD_ID = "995e7fd9-a697-472f-b956-73d89c5acf58"; // a UUID — NOT a secret

describe("secret classification", () => {
  it("matches known signatures", () => {
    expect(looksLikeSecret(AWS).kind).toBe("aws-access-key");
    expect(looksLikeSecret(JWT).kind).toBe("jwt");
  });

  it("does NOT flag a UUID (cloudId), config words, or short strings", () => {
    expect(looksLikeSecret(CLOUD_ID).isSecret).toBe(false);
    expect(looksLikeSecret("workspace-write").isSecret).toBe(false);
    expect(looksLikeSecret("on-failure").isSecret).toBe(false);
    expect(looksLikeSecret("/Users/me/Documents/project").isSecret).toBe(false);
    expect(looksLikeSecret("hello").isSecret).toBe(false);
  });

  it("finds signatures embedded in free text", () => {
    const hits = scanTextForSecrets(`export AWS_KEY=${AWS}\nsome prose here`);
    expect(hits.some((h) => h.kind === "aws-access-key")).toBe(true);
  });
});

describe("redaction invariant", () => {
  it("fingerprints never contain the raw value", () => {
    const fp = fingerprint(looksLikeSecret(AWS));
    expect(fp).not.toContain(AWS);
    expect(fp).toContain("aws-access-key");
  });

  it("redactSecretsInText removes the raw value", () => {
    const out = redactSecretsInText(`token=${JWT} done`);
    expect(out).not.toContain(JWT);
    expect(out).toContain("redacted:jwt");
  });

  it("assertNoSecretLeak throws on a leak and passes when clean", () => {
    expect(() => assertNoSecretLeak(`leaked ${AWS}`, [AWS])).toThrow();
    expect(() => assertNoSecretLeak(redactSecretsInText(`token ${AWS}`), [AWS])).not.toThrow();
  });
});
