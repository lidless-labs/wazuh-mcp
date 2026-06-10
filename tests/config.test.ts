import { afterEach, describe, expect, it, vi } from "vitest";
import { getConfig } from "../src/config.js";

function setRequiredEnv(): void {
  vi.stubEnv("WAZUH_URL", "https://wazuh.example.com:55000");
  vi.stubEnv("WAZUH_USERNAME", "admin");
  vi.stubEnv("WAZUH_PASSWORD", "secret");
}

describe("getConfig", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should parse timeout as milliseconds", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_TIMEOUT", "45");

    expect(getConfig().timeout).toBe(45000);
  });

  it("should reject invalid timeout values", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_TIMEOUT", "0");

    expect(() => getConfig()).toThrow("WAZUH_TIMEOUT must be a positive integer");
  });

  it("should reject partially numeric timeout values", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_TIMEOUT", "30s");

    expect(() => getConfig()).toThrow("WAZUH_TIMEOUT must be a positive integer");
  });

  it("should parse indexer timeout as milliseconds", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");
    vi.stubEnv("WAZUH_INDEXER_PASSWORD", "indexer-secret");
    vi.stubEnv("WAZUH_INDEXER_TIMEOUT", "12");

    expect(getConfig().indexer?.timeout).toBe(12000);
  });

  it("should reject invalid indexer timeout values", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");
    vi.stubEnv("WAZUH_INDEXER_PASSWORD", "indexer-secret");
    vi.stubEnv("WAZUH_INDEXER_TIMEOUT", "later");

    expect(() => getConfig()).toThrow("WAZUH_INDEXER_TIMEOUT must be a positive integer");
  });

  it("should verify TLS by default when WAZUH_VERIFY_SSL is unset", () => {
    setRequiredEnv();

    expect(getConfig().verifySsl).toBe(true);
  });

  it("should honor an explicit WAZUH_VERIFY_SSL=false for self-signed labs", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_VERIFY_SSL", "false");

    expect(getConfig().verifySsl).toBe(false);
  });

  it.each(["0", "no", "off", "FALSE"])(
    "should treat WAZUH_VERIFY_SSL=%s as verification disabled",
    (value) => {
      setRequiredEnv();
      vi.stubEnv("WAZUH_VERIFY_SSL", value);

      expect(getConfig().verifySsl).toBe(false);
    }
  );

  it("should keep verification enabled for WAZUH_VERIFY_SSL=true", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_VERIFY_SSL", "true");

    expect(getConfig().verifySsl).toBe(true);
  });

  it("should verify the indexer TLS by default when its flag is unset", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");
    vi.stubEnv("WAZUH_INDEXER_PASSWORD", "indexer-secret");

    expect(getConfig().indexer?.verifySsl).toBe(true);
  });

  it("should honor an explicit WAZUH_INDEXER_VERIFY_SSL=false", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");
    vi.stubEnv("WAZUH_INDEXER_PASSWORD", "indexer-secret");
    vi.stubEnv("WAZUH_INDEXER_VERIFY_SSL", "false");

    expect(getConfig().indexer?.verifySsl).toBe(false);
  });

  it("should fail fast when the indexer URL is set without a password", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");

    expect(() => getConfig()).toThrow(
      "WAZUH_INDEXER_PASSWORD environment variable is required when WAZUH_INDEXER_URL is set"
    );
  });

  it("should reject an empty indexer password", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");
    vi.stubEnv("WAZUH_INDEXER_PASSWORD", "");

    expect(() => getConfig()).toThrow(
      "WAZUH_INDEXER_PASSWORD environment variable is required when WAZUH_INDEXER_URL is set"
    );
  });

  it("should not require an indexer password when no indexer URL is set", () => {
    setRequiredEnv();

    expect(getConfig().indexer).toBeUndefined();
  });
});
