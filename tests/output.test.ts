import { afterEach, describe, expect, it, vi } from "vitest";
import { formatToolResponse } from "../src/tools/output.js";

describe("formatToolResponse", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should preserve normal JSON responses", () => {
    expect(formatToolResponse({ ok: true })).toBe(JSON.stringify({ ok: true }, null, 2));
  });

  it("should return truncation metadata when a response exceeds the byte limit", () => {
    vi.stubEnv("WAZUH_MCP_MAX_RESPONSE_BYTES", "200");

    const text = formatToolResponse({ items: ["x".repeat(1000)] });
    const parsed = JSON.parse(text) as {
      output: {
        response_truncated: boolean;
        max_response_bytes: number;
        original_response_bytes: number;
      };
      preview: string;
    };

    expect(parsed.output.response_truncated).toBe(true);
    expect(parsed.output.max_response_bytes).toBe(200);
    expect(parsed.output.original_response_bytes).toBeGreaterThan(200);
    expect(parsed.preview).toContain("items");
  });
});
