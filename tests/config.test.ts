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
    vi.stubEnv("WAZUH_INDEXER_TIMEOUT", "12");

    expect(getConfig().indexer?.timeout).toBe(12000);
  });

  it("should reject invalid indexer timeout values", () => {
    setRequiredEnv();
    vi.stubEnv("WAZUH_INDEXER_URL", "https://indexer.example.com:9200");
    vi.stubEnv("WAZUH_INDEXER_TIMEOUT", "later");

    expect(() => getConfig()).toThrow("WAZUH_INDEXER_TIMEOUT must be a positive integer");
  });
});
