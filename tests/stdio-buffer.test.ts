import { afterEach, describe, expect, it, vi } from "vitest";
import { maxStdioBufferBytes } from "../src/mcp-server.js";

describe("maxStdioBufferBytes", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should default to 8 MiB", () => {
    expect(maxStdioBufferBytes()).toBe(8 * 1024 * 1024);
  });

  it("should honor a valid WAZUH_MCP_MAX_STDIO_BUFFER_BYTES override", () => {
    vi.stubEnv("WAZUH_MCP_MAX_STDIO_BUFFER_BYTES", "1048576");
    expect(maxStdioBufferBytes()).toBe(1048576);
  });

  it("should fall back to the default for non-positive-integer values", () => {
    for (const raw of ["0", "-5", "1.5", "not-a-number", ""]) {
      vi.stubEnv("WAZUH_MCP_MAX_STDIO_BUFFER_BYTES", raw);
      expect(maxStdioBufferBytes()).toBe(8 * 1024 * 1024);
    }
  });
});
