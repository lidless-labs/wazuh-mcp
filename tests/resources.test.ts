import { describe, it, expect, vi, beforeEach } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerResources } from "../src/resources.js";
import { UNTRUSTED_DATA_NOTE } from "../src/tools/output.js";
import type { WazuhClient } from "../src/client.js";
import type { WazuhIndexerClient } from "../src/indexer-client.js";

type ResourceResult = {
  contents: Array<{ uri: string; mimeType: string; text: string }>;
};
type ResourceHandler = () => Promise<ResourceResult>;

// Capture resource handlers registered via server.resource()
function captureResources(
  mockClient: Partial<WazuhClient>,
  mockIndexerClient?: Partial<WazuhIndexerClient>
): Map<string, ResourceHandler> {
  const resources = new Map<string, ResourceHandler>();

  const mockServer = {
    resource: (
      _name: string,
      uri: string,
      _metadata: unknown,
      handler: ResourceHandler
    ) => {
      resources.set(uri, handler);
    },
  } as unknown as McpServer;

  registerResources(
    mockServer,
    mockClient as WazuhClient,
    mockIndexerClient as WazuhIndexerClient | undefined
  );
  return resources;
}

function parseResource(result: ResourceResult, uri: string): Record<string, unknown> {
  expect(result.contents).toHaveLength(1);
  expect(result.contents[0].uri).toBe(uri);
  expect(result.contents[0].mimeType).toBe("application/json");
  return JSON.parse(result.contents[0].text) as Record<string, unknown>;
}

describe("Resources", () => {
  let mockClient: Partial<WazuhClient>;

  beforeEach(() => {
    mockClient = {
      getAgents: vi.fn(),
      getRules: vi.fn(),
    };
  });

  it("registers the three documented resource URIs", () => {
    const resources = captureResources(mockClient);
    expect([...resources.keys()].sort()).toEqual([
      "wazuh://agents",
      "wazuh://alerts/recent",
      "wazuh://rules/summary",
    ]);
  });

  describe("wazuh://agents", () => {
    it("returns a trimmed agent list with the total", async () => {
      vi.mocked(mockClient.getAgents!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: "001",
              name: "server-1",
              ip: "192.0.2.1",
              status: "active",
              group: ["default"],
              os: { name: "Ubuntu", version: "22.04", platform: "linux" },
              version: "Wazuh v4.7.0",
              lastKeepAlive: "2026-01-01T00:00:00Z",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const resources = captureResources(mockClient);
      const data = parseResource(
        await resources.get("wazuh://agents")!(),
        "wazuh://agents"
      );

      expect(mockClient.getAgents).toHaveBeenCalledWith({ limit: 100 });
      expect(data).toEqual({
        agents: [
          {
            id: "001",
            name: "<untrusted_siem_data>server-1</untrusted_siem_data>",
            status: "active",
            group: ["default"],
            os: "<untrusted_siem_data>Ubuntu</untrusted_siem_data>",
            version: "<untrusted_siem_data>Wazuh v4.7.0</untrusted_siem_data>",
            last_keepalive: "2026-01-01T00:00:00Z",
          },
        ],
        total: 1,
        output: { untrusted_data_note: UNTRUSTED_DATA_NOTE },
      });
      // IP addresses are sensitive and must not leak through the resource.
      expect(JSON.stringify(data)).not.toContain("192.0.2.1");
    });
  });

  describe("wazuh://rules/summary", () => {
    it("returns rules sorted by level with the total", async () => {
      vi.mocked(mockClient.getRules!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: 100100,
              description: "Critical rule",
              level: 15,
              groups: ["attack"],
              filename: "local_rules.xml",
              status: "enabled",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      } as Awaited<ReturnType<WazuhClient["getRules"]>>);

      const resources = captureResources(mockClient);
      const data = parseResource(
        await resources.get("wazuh://rules/summary")!(),
        "wazuh://rules/summary"
      );

      expect(mockClient.getRules).toHaveBeenCalledWith({ limit: 100, sort: "-level" });
      expect(data).toEqual({
        rules: [
          { id: 100100, description: "Critical rule", level: 15, groups: ["attack"] },
        ],
        total: 1,
      });
    });
  });

  describe("wazuh://alerts/recent", () => {
    it("returns a configuration message instead of throwing when the indexer is not configured", async () => {
      const resources = captureResources(mockClient);
      const result = await resources.get("wazuh://alerts/recent")!();
      const data = parseResource(result, "wazuh://alerts/recent");

      expect(Object.keys(data)).toEqual(["error"]);
      expect(data.error).toContain("WAZUH_INDEXER_URL");
      expect(data.error).toContain("Wazuh Indexer");
    });

    it("returns recent alerts with untrusted rule descriptions when the indexer is configured", async () => {
      const mockIndexer: Partial<WazuhIndexerClient> = {
        getRecentAlerts: vi.fn().mockResolvedValue({
          alerts: [
            {
              id: "alert-1",
              timestamp: "2026-01-01T00:00:00Z",
              rule: { id: "5710", level: 5, description: "sshd: invalid user" },
              agent: { id: "001", name: "server-1" },
              full_log: "raw log that must not be exposed",
            },
          ],
          total: 1,
        }),
      };

      const resources = captureResources(mockClient, mockIndexer);
      const result = await resources.get("wazuh://alerts/recent")!();
      const data = parseResource(result, "wazuh://alerts/recent");

      expect(mockIndexer.getRecentAlerts).toHaveBeenCalledWith(25, 0);
      expect(data).toEqual({
        alerts: [
          {
            id: "alert-1",
            timestamp: "2026-01-01T00:00:00Z",
            rule_id: "5710",
            rule_level: 5,
            rule_description: "<untrusted_siem_data>sshd: invalid user</untrusted_siem_data>",
            agent_id: "001",
            agent_name: "<untrusted_siem_data>server-1</untrusted_siem_data>",
          },
        ],
        total: 1,
        output: { untrusted_data_note: UNTRUSTED_DATA_NOTE },
      });
      expect(result.contents[0].text).not.toContain("raw log that must not be exposed");
    });
  });
});
