import { describe, expect, it } from "vitest";
import { isSecretFileName, redactSecrets, sanitize } from "../server/redact.js";

describe("redact", () => {
  it("redacts KEY= assignments", () => {
    expect(redactSecrets("OPENAI_API_KEY=sk-abc123XYZ456")).not.toContain("abc123");
    expect(redactSecrets("OPENAI_API_KEY=sk-abc123XYZ456")).toContain("[REDACTED]");
  });
  it("redacts known token shapes", () => {
    for (const t of ["sk-abcdefghijklmnop1234", "ghp_abcdefghijklmnop1234", "AKIAIOSFODNN7EXAMPLE"]) {
      expect(redactSecrets(`token ${t} here`)).not.toContain(t);
    }
  });
  it("redacts PEM blocks", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg==\n-----END RSA PRIVATE KEY-----";
    expect(redactSecrets(pem)).not.toContain("MIIBOg");
  });
  it("redacts URL credentials", () => {
    expect(redactSecrets("https://user:s3cret@host/x")).not.toContain("s3cret");
  });
  it("flags secret filenames", () => {
    expect(isSecretFileName("/w/.env")).toBe(true);
    expect(isSecretFileName("/w/.env.local")).toBe(true);
    expect(isSecretFileName("/home/u/.ssh/id_rsa")).toBe(true);
    expect(isSecretFileName("/w/cert.pem")).toBe(true);
    expect(isSecretFileName("/w/src/index.ts")).toBe(false);
  });
  it("sanitize truncates", () => {
    expect(sanitize("x".repeat(5000), 100).length).toBeLessThan(5000);
  });
});
