import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { WazuhClient } from "../src/client.js";
import type { WazuhConfig } from "../src/config.js";
import { createWazuhMcpServer } from "../src/mcp-server.js";
import { READ_ONLY_TOOL_ANNOTATIONS } from "../src/tools/annotations.js";

const mockConfig: WazuhConfig = {
  url: "https://wazuh.example.com:55000",
  username: "wazuh-mcp-readonly",
  password: "secret",
  verifySsl: true,
  timeout: 30_000,
};

// Listing tools never calls Wazuh, so an empty client object is enough and the
// suite stays fully mocked.
async function listToolsOverSdk() {
  const server = createWazuhMcpServer({ config: mockConfig, client: {} as WazuhClient });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "annotations-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const { tools } = await client.listTools();
  return { tools, close: () => client.close() };
}

describe("MCP tool annotations", () => {
  let close: (() => Promise<void>) | undefined;

  afterEach(async () => {
    await close?.();
    close = undefined;
  });

  it("defines the shared annotations once as read-only and open-world", () => {
    expect(READ_ONLY_TOOL_ANNOTATIONS).toEqual({ readOnlyHint: true, openWorldHint: true });
    expect(Object.isFrozen(READ_ONLY_TOOL_ANNOTATIONS)).toBe(true);
  });

  it("lists exactly 28 tools, each annotated readOnlyHint true and openWorldHint true", async () => {
    const listed = await listToolsOverSdk();
    close = listed.close;
    const { tools } = listed;

    expect(tools).toHaveLength(28);
    expect(new Set(tools.map((tool) => tool.name)).size).toBe(28);

    const unannotated = tools
      .filter(
        (tool) => tool.annotations?.readOnlyHint !== true || tool.annotations?.openWorldHint !== true
      )
      .map((tool) => tool.name);
    expect(unannotated).toEqual([]);

    // A tool that warns about attacker-influenced output must never claim a
    // closed world, even if a later change splits the annotations per tool.
    const untrusted = tools.filter((tool) => tool.description?.includes("untrusted_siem_data"));
    expect(untrusted.length).toBeGreaterThan(0);
    expect(
      untrusted.filter((tool) => tool.annotations?.openWorldHint !== true).map((tool) => tool.name)
    ).toEqual([]);
  });
});
