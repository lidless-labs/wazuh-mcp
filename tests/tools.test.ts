import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAgentTools } from "../src/tools/agents.js";
import { registerAlertTools } from "../src/tools/alerts.js";
import { registerRuleTools } from "../src/tools/rules.js";
import { registerDecoderTools } from "../src/tools/decoders.js";
import { registerVersionTools } from "../src/tools/version.js";
import { registerDiagnosticTools } from "../src/tools/diagnostics.js";
import { registerGroupTools } from "../src/tools/groups.js";
import { registerManagerTools } from "../src/tools/manager.js";
import { registerSyscheckTools } from "../src/tools/syscheck.js";
import { registerSyscollectorTools } from "../src/tools/syscollector.js";
import { registerVulnerabilityTools } from "../src/tools/vulnerabilities.js";
import type { WazuhClient } from "../src/client.js";
import type { WazuhConfig } from "../src/config.js";
import type { WazuhIndexerClient } from "../src/indexer-client.js";

type ToolHandler = (args: Record<string, unknown>) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

// Capture tool handlers registered via server.tool()
function captureTools(
  registerFn: (server: McpServer, client: WazuhClient, indexerClient?: WazuhIndexerClient) => void,
  mockClient: Partial<WazuhClient>,
  mockIndexerClient?: Partial<WazuhIndexerClient>
): Map<string, ToolHandler> {
  const tools = new Map<string, ToolHandler>();

  const mockServer = {
    tool: (
      name: string,
      _description: string,
      _schema: unknown,
      handler: ToolHandler
    ) => {
      tools.set(name, handler);
    },
  } as unknown as McpServer;

  registerFn(
    mockServer,
    mockClient as WazuhClient,
    mockIndexerClient as WazuhIndexerClient | undefined
  );
  return tools;
}

function parseToolResult(result: {
  content: Array<{ type: string; text: string }>;
}): unknown {
  return JSON.parse(result.content[0].text);
}

function captureDiagnosticTools(
  mockClient: Partial<WazuhClient>,
  mockConfig: WazuhConfig,
  mockIndexerClient?: Partial<WazuhIndexerClient>
): Map<string, ToolHandler> {
  const tools = new Map<string, ToolHandler>();

  const mockServer = {
    tool: (
      name: string,
      _description: string,
      _schema: unknown,
      handler: ToolHandler
    ) => {
      tools.set(name, handler);
    },
  } as unknown as McpServer;

  registerDiagnosticTools(
    mockServer,
    mockClient as WazuhClient,
    mockConfig,
    mockIndexerClient as WazuhIndexerClient | undefined
  );
  return tools;
}

function captureVulnerabilityTools(
  mockIndexerClient?: Partial<WazuhIndexerClient>
): Map<string, ToolHandler> {
  const tools = new Map<string, ToolHandler>();

  const mockServer = {
    tool: (
      name: string,
      _description: string,
      _schema: unknown,
      handler: ToolHandler
    ) => {
      tools.set(name, handler);
    },
  } as unknown as McpServer;

  registerVulnerabilityTools(
    mockServer,
    mockIndexerClient as WazuhIndexerClient | undefined
  );
  return tools;
}

describe("Agent Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getAgents: vi.fn(),
      getAgent: vi.fn(),
      getAgentStats: vi.fn(),
    };
    tools = captureTools(registerAgentTools, mockClient);
  });

  describe("list_agents", () => {
    it("should return formatted agent list", async () => {
      vi.mocked(mockClient.getAgents!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: "001",
              name: "server-1",
              ip: "10.0.0.1",
              status: "active",
              group: ["default"],
              os: { name: "Ubuntu", version: "22.04", platform: "linux" },
              version: "Wazuh v4.7.0",
              manager: "wazuh-manager",
              node_name: "node01",
              dateAdd: "2026-01-01T00:00:00Z",
              lastKeepAlive: "2026-01-15T10:00:00Z",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("list_agents")!;
      const result = await handler({ limit: 10, offset: 0 });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data).toHaveProperty("agents");
      expect(data).toHaveProperty("total", 1);
      const agents = data.agents as Array<Record<string, unknown>>;
      expect(agents[0].name).toBe("server-1");
      expect(agents[0].os_name).toBe("Ubuntu");
      expect(agents[0].ip).toBeUndefined();
      expect((data.output as Record<string, unknown>).ip_included).toBe(false);
    });

    it("should include agent IPs only when requested", async () => {
      vi.mocked(mockClient.getAgents!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: "001",
              name: "server-1",
              ip: "10.0.0.1",
              status: "active",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("list_agents")!;
      const result = await handler({ limit: 10, offset: 0, include_ip: true });
      const data = parseToolResult(result) as Record<string, unknown>;
      const agents = data.agents as Array<Record<string, unknown>>;

      expect(agents[0].ip).toBe("10.0.0.1");
      expect((data.output as Record<string, unknown>).ip_included).toBe(true);
    });

    it("should pass status filter to client", async () => {
      vi.mocked(mockClient.getAgents!).mockResolvedValue({
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("list_agents")!;
      await handler({ status: "active", limit: 10, offset: 0 });

      expect(mockClient.getAgents).toHaveBeenCalledWith(
        expect.objectContaining({ status: "active" })
      );
    });

    it("should handle errors gracefully", async () => {
      vi.mocked(mockClient.getAgents!).mockRejectedValue(
        new Error("Connection refused")
      );

      const handler = tools.get("list_agents")!;
      const result = await handler({ limit: 10, offset: 0 });

      expect(result.isError).toBe(true);
      const data = parseToolResult(result) as Record<string, unknown>;
      expect(data.error).toBe("Connection refused");
    });

    it("should sanitize secrets in errors that bypass the client wrappers", async () => {
      vi.mocked(mockClient.getAgents!).mockRejectedValue(
        new Error(
          "Unexpected token in JSON: Authorization: Bearer eyJhbGciOi.eyJzdWIi.c2lnbmF0dXJl at https://admin:hunter2@wazuh.example.com:55000/agents"
        )
      );

      const handler = tools.get("list_agents")!;
      const result = await handler({ limit: 10, offset: 0 });

      expect(result.isError).toBe(true);
      const rawText = result.content[0].text;
      expect(rawText).not.toContain("eyJhbGciOi");
      expect(rawText).not.toContain("hunter2");
      expect(rawText).toContain("[REDACTED]");
    });

    it("should sanitize non-Error throws into the fallback message", async () => {
      vi.mocked(mockClient.getAgents!).mockRejectedValue({ status: 500 });

      const handler = tools.get("list_agents")!;
      const result = await handler({ limit: 10, offset: 0 });

      expect(result.isError).toBe(true);
      const data = parseToolResult(result) as Record<string, unknown>;
      expect(data.error).toBe("Unexpected error");
    });
  });

  describe("get_agent", () => {
    it("should return agent details", async () => {
      vi.mocked(mockClient.getAgent!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: "001",
              name: "server-1",
              ip: "10.0.0.1",
              status: "active",
              os: { name: "CentOS", version: "8", platform: "linux" },
              version: "Wazuh v4.7.0",
              registerIP: "any",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_agent")!;
      const result = await handler({ agent_id: "001" });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.id).toBe("001");
      expect(data.os_name).toBe("CentOS");
      expect(data.ip).toBeUndefined();
      expect(data.register_ip).toBeUndefined();
    });

    it("should include agent IP details only when requested", async () => {
      vi.mocked(mockClient.getAgent!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: "001",
              name: "server-1",
              ip: "10.0.0.1",
              status: "active",
              os: { name: "CentOS", version: "8", platform: "linux" },
              registerIP: "any",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_agent")!;
      const result = await handler({ agent_id: "001", include_ip: true });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.ip).toBe("10.0.0.1");
      expect(data.register_ip).toBe("any");
      expect((data.output as Record<string, unknown>).ip_included).toBe(true);
    });

    it("should return error for missing agent", async () => {
      vi.mocked(mockClient.getAgent!).mockResolvedValue({
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_agent")!;
      const result = await handler({ agent_id: "999" });

      expect(result.isError).toBe(true);
      const data = parseToolResult(result) as Record<string, unknown>;
      expect(data.error).toContain("999");
    });
  });

  describe("get_agent_stats", () => {
    it("should return agent stats with name", async () => {
      vi.mocked(mockClient.getAgent!).mockResolvedValue({
        data: {
          affected_items: [
            { id: "001", name: "server-1", ip: "10.0.0.1", status: "active" },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });
      vi.mocked(mockClient.getAgentStats!).mockResolvedValue({
        data: {
          affected_items: [
            {
              cpu: { usage_percent: 25.5, cores: 4 },
              memory: {
                total_bytes: 8589934592,
                used_bytes: 4294967296,
                free_bytes: 4294967296,
                usage_percent: 50.0,
              },
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_agent_stats")!;
      const result = await handler({ agent_id: "001" });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.agent_id).toBe("001");
      expect(data.agent_name).toBe("server-1");
      expect(data.cpu).toBeDefined();
      expect(data.memory).toBeDefined();
    });

    it("should return error for missing agent", async () => {
      vi.mocked(mockClient.getAgent!).mockResolvedValue({
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_agent_stats")!;
      const result = await handler({ agent_id: "999" });

      expect(result.isError).toBe(true);
    });
  });
});

describe("Alert Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let mockIndexerClient: Partial<WazuhIndexerClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {};
    mockIndexerClient = {
      getRecentAlerts: vi.fn(),
      getAlert: vi.fn(),
      fullTextSearch: vi.fn(),
    };
    tools = captureTools(registerAlertTools, mockClient, mockIndexerClient);
  });

  describe("get_alerts", () => {
    it("should return formatted alerts", async () => {
      vi.mocked(mockIndexerClient.getRecentAlerts!).mockResolvedValue({
        alerts: [
          {
            id: "alert-123",
            timestamp: "2026-01-15T10:30:00.000Z",
            rule: {
              id: "5710",
              level: 5,
              description: "sshd: attempt to login using a denied user",
              groups: ["sshd", "authentication_failed"],
            },
            agent: { id: "001", name: "server-1" },
            location: "/var/log/auth.log",
            decoder: { name: "sshd" },
            full_log: "Jan 15 10:30:00 server sshd: Failed password",
          },
        ],
        total: 1,
      });

      const handler = tools.get("get_alerts")!;
      const result = await handler({ limit: 10, offset: 0 });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data).toHaveProperty("alerts");
      const alerts = data.alerts as Array<Record<string, unknown>>;
      expect(alerts[0].rule_id).toBe("5710");
      expect(alerts[0].rule_level).toBe(5);
      expect(alerts[0].agent_name).toBe("server-1");
      expect(alerts[0].full_log).toBeUndefined();
      expect((data.output as Record<string, unknown>).full_log_included).toBe(false);
    });

    it("should include alert full logs only when requested", async () => {
      vi.mocked(mockIndexerClient.getRecentAlerts!).mockResolvedValue({
        alerts: [
          {
            id: "alert-123",
            timestamp: "2026-01-15T10:30:00.000Z",
            rule: { id: "5710", level: 5 },
            full_log: "sensitive raw alert log",
          },
        ],
        total: 1,
      });

      const handler = tools.get("get_alerts")!;
      const result = await handler({ limit: 10, offset: 0, include_full_log: true });
      const data = parseToolResult(result) as Record<string, unknown>;
      const alerts = data.alerts as Array<Record<string, unknown>>;

      expect(alerts[0].full_log).toBe("sensitive raw alert log");
      expect((data.output as Record<string, unknown>).full_log_included).toBe(true);
    });

    it("should pass level filter through to the indexer client", async () => {
      vi.mocked(mockIndexerClient.getRecentAlerts!).mockResolvedValue({
        alerts: [],
        total: 0,
      });

      const handler = tools.get("get_alerts")!;
      await handler({ limit: 10, offset: 0, level: 12 });

      expect(mockIndexerClient.getRecentAlerts).toHaveBeenCalledWith(
        10,
        0,
        expect.objectContaining({ level: 12 })
      );
    });

    it("should pass timestamp sort direction through to the indexer client", async () => {
      vi.mocked(mockIndexerClient.getRecentAlerts!).mockResolvedValue({
        alerts: [],
        total: 0,
      });

      const handler = tools.get("get_alerts")!;
      const result = await handler({ limit: 10, offset: 0, sort: "+timestamp" });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(mockIndexerClient.getRecentAlerts).toHaveBeenCalledWith(
        10,
        0,
        expect.objectContaining({ sortOrder: "asc" })
      );
      expect(data.sort).toBe("+timestamp");
    });

    it("should pass time range filters through to the indexer client", async () => {
      vi.mocked(mockIndexerClient.getRecentAlerts!).mockResolvedValue({
        alerts: [],
        total: 0,
      });

      const handler = tools.get("get_alerts")!;
      await handler({
        limit: 10,
        offset: 0,
        start_time: "2026-01-01T00:00:00.000Z",
        end_time: "2026-01-02T00:00:00.000Z",
      });

      expect(mockIndexerClient.getRecentAlerts).toHaveBeenCalledWith(
        10,
        0,
        expect.objectContaining({
          start_time: "2026-01-01T00:00:00.000Z",
          end_time: "2026-01-02T00:00:00.000Z",
        })
      );
    });
  });

  describe("get_alert", () => {
    it("should return single alert", async () => {
      vi.mocked(mockIndexerClient.getAlert!).mockResolvedValue({
        id: "alert-123",
        timestamp: "2026-01-15T10:30:00.000Z",
        rule: { id: "5710", level: 5, description: "SSH login attempt" },
        agent: { id: "001", name: "server-1" },
        full_log: "sensitive raw alert log",
        data: { user: "root" },
      } as never);

      const handler = tools.get("get_alert")!;
      const result = await handler({ alert_id: "alert-123" });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.id).toBe("alert-123");
      expect(data.full_log).toBeUndefined();
      expect(data.data).toBeUndefined();
      expect((data.output as Record<string, unknown>).full_log_included).toBe(false);
      expect((data.output as Record<string, unknown>).raw_data_included).toBe(false);
    });

    it("should include single alert raw fields only when requested", async () => {
      vi.mocked(mockIndexerClient.getAlert!).mockResolvedValue({
        id: "alert-123",
        timestamp: "2026-01-15T10:30:00.000Z",
        rule: { id: "5710", level: 5, description: "SSH login attempt" },
        full_log: "sensitive raw alert log",
        data: { user: "root" },
      } as never);

      const handler = tools.get("get_alert")!;
      const result = await handler({
        alert_id: "alert-123",
        include_full_log: true,
        include_raw_data: true,
      });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.full_log).toBe("sensitive raw alert log");
      expect(data.data).toEqual({ user: "root" });
    });

    it("should return error when alert not found", async () => {
      vi.mocked(mockIndexerClient.getAlert!).mockResolvedValue(null);

      const handler = tools.get("get_alert")!;
      const result = await handler({ alert_id: "nonexistent" });

      expect(result.isError).toBe(true);
    });
  });

  describe("search_alerts", () => {
    it("should pass query as search parameter", async () => {
      vi.mocked(mockIndexerClient.fullTextSearch!).mockResolvedValue({
        alerts: [],
        total: 0,
      });

      const handler = tools.get("search_alerts")!;
      await handler({
        query: "brute force",
        limit: 10,
        offset: 0,
      });

      expect(mockIndexerClient.fullTextSearch).toHaveBeenCalledWith(
        "brute force",
        10,
        0,
        { level: undefined, agent_id: undefined }
      );
    });

    it("should include query in response", async () => {
      vi.mocked(mockIndexerClient.fullTextSearch!).mockResolvedValue({
        alerts: [],
        total: 0,
      });

      const handler = tools.get("search_alerts")!;
      const result = await handler({
        query: "ssh failed",
        limit: 10,
        offset: 0,
      });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.query).toBe("ssh failed");
      expect((data.output as Record<string, unknown>).full_log_included).toBe(false);
    });
  });
});

describe("Diagnostic Tools", () => {
  const mockConfig: WazuhConfig = {
    url: "https://api-user:api-pass@wazuh.example.com:55000",
    username: "admin",
    password: "secret-password",
    verifySsl: false,
    timeout: 30000,
    indexer: {
      url: "https://index-user:index-pass@indexer.example.com:9200",
      username: "index-admin",
      password: "indexer-secret",
      verifySsl: false,
      timeout: 30000,
    },
  };

  it("should return sanitized configuration without connectivity checks", async () => {
    const mockClient: Partial<WazuhClient> = {
      authenticate: vi.fn(),
      getVersion: vi.fn(),
    };
    const mockIndexerClient: Partial<WazuhIndexerClient> = {
      getInfo: vi.fn(),
      indexExists: vi.fn(),
    };
    const tools = captureDiagnosticTools(mockClient, mockConfig, mockIndexerClient);

    const handler = tools.get("diagnose_wazuh_connection")!;
    const result = await handler({ check_connectivity: false });
    const rawText = result.content[0].text;
    const data = parseToolResult(result) as Record<string, unknown>;

    expect(rawText).not.toContain("secret-password");
    expect(rawText).not.toContain("indexer-secret");
    expect(rawText).not.toContain("api-pass");
    expect(rawText).not.toContain("index-pass");
    expect(data.status).toBe("warning");
    expect(mockClient.getVersion).not.toHaveBeenCalled();
    expect(mockIndexerClient.getInfo).not.toHaveBeenCalled();
  });

  it("should report manager and indexer connectivity success", async () => {
    const mockClient: Partial<WazuhClient> = {
      authenticate: vi.fn().mockResolvedValue("token"),
      getVersion: vi.fn().mockResolvedValue({
        data: {
          title: "Wazuh API REST",
          api_version: "4.7.0",
          revision: 40700,
          license_name: "GPL 2.0",
          license_url: "https://example.com/license",
          hostname: "wazuh-manager",
          timestamp: "2026-01-15T10:00:00Z",
        },
        error: 0,
        message: "ok",
      }),
    };
    const mockIndexerClient: Partial<WazuhIndexerClient> = {
      getInfo: vi.fn().mockResolvedValue({
        cluster_name: "wazuh-indexer",
        version: { number: "2.11.0" },
      }),
      indexExists: vi.fn().mockResolvedValue(true),
    };
    const tools = captureDiagnosticTools(
      mockClient,
      { ...mockConfig, verifySsl: true, indexer: { ...mockConfig.indexer!, verifySsl: true } },
      mockIndexerClient
    );

    const handler = tools.get("diagnose_wazuh_connection")!;
    const result = await handler({ check_connectivity: true });
    const data = parseToolResult(result) as Record<string, unknown>;

    expect(result.isError).toBe(false);
    expect(data.status).toBe("ok");
    expect(mockClient.authenticate).toHaveBeenCalledOnce();
    expect(mockClient.getVersion).toHaveBeenCalledOnce();
    expect(mockIndexerClient.getInfo).toHaveBeenCalledOnce();
    expect(mockIndexerClient.indexExists).toHaveBeenCalledWith("wazuh-alerts-*");
    expect(mockIndexerClient.indexExists).toHaveBeenCalledWith("wazuh-states-vulnerabilities*");
  });

  it("should mark diagnostics as an error when connectivity fails", async () => {
    const mockClient: Partial<WazuhClient> = {
      authenticate: vi.fn().mockRejectedValue(new Error("ECONNREFUSED")),
      getVersion: vi.fn(),
    };
    const tools = captureDiagnosticTools(
      mockClient,
      { ...mockConfig, verifySsl: true, indexer: undefined }
    );

    const handler = tools.get("diagnose_wazuh_connection")!;
    const result = await handler({ check_connectivity: true });
    const data = parseToolResult(result) as Record<string, unknown>;

    expect(result.isError).toBe(true);
    expect(data.status).toBe("error");
    expect(result.content[0].text).toContain("ECONNREFUSED");
    expect(mockClient.getVersion).not.toHaveBeenCalled();
  });
});

describe("Vulnerability Tools", () => {
  let mockIndexerClient: Partial<WazuhIndexerClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockIndexerClient = {
      searchVulnerabilities: vi.fn(),
    };
    tools = captureVulnerabilityTools(mockIndexerClient);
  });

  it("should return a configuration error when indexer is missing", async () => {
    const noIndexerTools = captureVulnerabilityTools();
    const handler = noIndexerTools.get("list_vulnerabilities")!;
    const result = await handler({ limit: 10, offset: 0 });

    expect(result.isError).toBe(true);
    const data = parseToolResult(result) as Record<string, unknown>;
    expect(data.error).toContain("WAZUH_INDEXER_URL");
  });

  it("should list formatted vulnerability inventory", async () => {
    vi.mocked(mockIndexerClient.searchVulnerabilities!).mockResolvedValue({
      vulnerabilities: [
        {
          id: "001_package_CVE-2020-14393",
          agent: { id: "001", name: "server-1" },
          package: { name: "perl-DBI", version: "1.627-4.el7", type: "rpm" },
          vulnerability: {
            id: "CVE-2020-14393",
            severity: "Low",
            detected_at: "2024-12-11T00:14:31.360Z",
            description: "Sensitive vulnerability description",
            score: { base: 3.6, version: "2.0" },
          },
        },
      ],
      total: 1,
    });

    const handler = tools.get("list_vulnerabilities")!;
    const result = await handler({
      limit: 10,
      offset: 0,
      cve_id: "CVE-2020-14393",
      agent_id: "001",
      severity: "Low",
    });
    const data = parseToolResult(result) as Record<string, unknown>;
    const vulnerabilities = data.vulnerabilities as Array<Record<string, unknown>>;

    expect(mockIndexerClient.searchVulnerabilities).toHaveBeenCalledWith(
      10,
      0,
      expect.objectContaining({
        cve_id: "CVE-2020-14393",
        agent_id: "001",
        severity: "Low",
      })
    );
    expect(vulnerabilities[0].cve_id).toBe("CVE-2020-14393");
    expect(vulnerabilities[0].package_name).toBe("perl-DBI");
    expect(vulnerabilities[0].description).toBeUndefined();
  });

  it("should include vulnerability descriptions only when requested", async () => {
    vi.mocked(mockIndexerClient.searchVulnerabilities!).mockResolvedValue({
      vulnerabilities: [
        {
          vulnerability: {
            id: "CVE-2020-14393",
            severity: "Low",
            description: "Sensitive vulnerability description",
          },
        },
      ],
      total: 1,
    });

    const handler = tools.get("search_vulnerabilities")!;
    const result = await handler({
      query: "perl",
      limit: 10,
      offset: 0,
      include_description: true,
    });
    const data = parseToolResult(result) as Record<string, unknown>;
    const vulnerabilities = data.vulnerabilities as Array<Record<string, unknown>>;

    expect(mockIndexerClient.searchVulnerabilities).toHaveBeenCalledWith(
      10,
      0,
      expect.objectContaining({ search: "perl" })
    );
    expect(vulnerabilities[0].description).toBe("Sensitive vulnerability description");
    expect((data.output as Record<string, unknown>).description_included).toBe(true);
  });
});

describe("Rule Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getRules: vi.fn(),
      getRule: vi.fn(),
    };
    tools = captureTools(registerRuleTools, mockClient);
  });

  describe("list_rules", () => {
    it("should return formatted rules", async () => {
      vi.mocked(mockClient.getRules!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: 5710,
              description: "sshd: attempt to login using a denied user",
              level: 5,
              groups: ["sshd"],
              pci_dss: ["10.2.4"],
              mitre: { id: ["T1110"], tactic: ["Credential Access"] },
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("list_rules")!;
      const result = await handler({ limit: 10, offset: 0 });
      const data = parseToolResult(result) as Record<string, unknown>;

      const rules = data.rules as Array<Record<string, unknown>>;
      expect(rules[0].id).toBe(5710);
      expect(rules[0].pci_dss).toEqual(["10.2.4"]);
    });
  });

  describe("get_rule", () => {
    it("should return rule details", async () => {
      vi.mocked(mockClient.getRule!).mockResolvedValue({
        data: {
          affected_items: [
            {
              id: 5710,
              description: "sshd: attempt to login using a denied user",
              level: 5,
              groups: ["sshd"],
              filename: "0095-sshd_rules.xml",
              status: "enabled",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_rule")!;
      const result = await handler({ rule_id: 5710 });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.id).toBe(5710);
      expect(data.filename).toBe("0095-sshd_rules.xml");
    });

    it("should return error for missing rule", async () => {
      vi.mocked(mockClient.getRule!).mockResolvedValue({
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_rule")!;
      const result = await handler({ rule_id: 99999 });

      expect(result.isError).toBe(true);
    });
  });

  describe("search_rules", () => {
    it("should pass description as search parameter", async () => {
      vi.mocked(mockClient.getRules!).mockResolvedValue({
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("search_rules")!;
      await handler({
        description: "authentication",
        limit: 10,
        offset: 0,
      });

      expect(mockClient.getRules).toHaveBeenCalledWith(
        expect.objectContaining({ search: "authentication" })
      );
    });

    it("should include description in response", async () => {
      vi.mocked(mockClient.getRules!).mockResolvedValue({
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("search_rules")!;
      const result = await handler({
        description: "ssh",
        limit: 10,
        offset: 0,
      });
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.description).toBe("ssh");
    });
  });
});

describe("Decoder Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getDecoders: vi.fn(),
    };
    tools = captureTools(registerDecoderTools, mockClient);
  });

  describe("list_decoders", () => {
    it("should return formatted decoders", async () => {
      vi.mocked(mockClient.getDecoders!).mockResolvedValue({
        data: {
          affected_items: [
            {
              name: "sshd",
              filename: "0310-ssh_decoders.xml",
              status: "enabled",
              position: 0,
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("list_decoders")!;
      const result = await handler({ limit: 10, offset: 0 });
      const data = parseToolResult(result) as Record<string, unknown>;

      const decoders = data.decoders as Array<Record<string, unknown>>;
      expect(decoders[0].name).toBe("sshd");
      expect(decoders[0].filename).toBe("0310-ssh_decoders.xml");
    });

    it("should pass name filter to client", async () => {
      vi.mocked(mockClient.getDecoders!).mockResolvedValue({
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("list_decoders")!;
      await handler({ name: "sshd", limit: 10, offset: 0 });

      expect(mockClient.getDecoders).toHaveBeenCalledWith(
        expect.objectContaining({ name: "sshd" })
      );
    });
  });
});

describe("Group Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getGroups: vi.fn(),
      getGroupAgents: vi.fn(),
    };
    tools = captureTools(registerGroupTools, mockClient);
  });

  it("should omit group agent IPs by default", async () => {
    vi.mocked(mockClient.getGroupAgents!).mockResolvedValue({
      data: {
        affected_items: [
          {
            id: "001",
            name: "server-1",
            ip: "10.0.0.1",
            status: "active",
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_group_agents")!;
    const result = await handler({ group_id: "default", limit: 10, offset: 0 });
    const data = parseToolResult(result) as Record<string, unknown>;
    const agents = data.agents as Array<Record<string, unknown>>;

    expect(agents[0].ip).toBeUndefined();
    expect((data.output as Record<string, unknown>).ip_included).toBe(false);
  });

  it("should include group agent IPs only when requested", async () => {
    vi.mocked(mockClient.getGroupAgents!).mockResolvedValue({
      data: {
        affected_items: [
          {
            id: "001",
            name: "server-1",
            ip: "10.0.0.1",
            status: "active",
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_group_agents")!;
    const result = await handler({
      group_id: "default",
      limit: 10,
      offset: 0,
      include_ip: true,
    });
    const data = parseToolResult(result) as Record<string, unknown>;
    const agents = data.agents as Array<Record<string, unknown>>;

    expect(agents[0].ip).toBe("10.0.0.1");
    expect((data.output as Record<string, unknown>).ip_included).toBe(true);
  });
});

describe("Manager Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getManagerLogs: vi.fn(),
      getManagerConfig: vi.fn(),
    };
    tools = captureTools(registerManagerTools, mockClient);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("should omit manager log descriptions by default", async () => {
    vi.mocked(mockClient.getManagerLogs!).mockResolvedValue({
      data: {
        affected_items: [
          {
            timestamp: "2026-01-15T10:00:00Z",
            tag: "wazuh-modulesd",
            level: "info",
            description: "sensitive host log line",
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_manager_logs")!;
    const result = await handler({ limit: 10, offset: 0 });
    const data = parseToolResult(result) as Record<string, unknown>;
    const logs = data.logs as Array<Record<string, unknown>>;

    expect(logs[0].description).toBeUndefined();
    expect((data.pagination as Record<string, unknown>).has_more).toBe(false);
    expect((data.output as Record<string, unknown>).description_included).toBe(false);
  });

  it("should include manager log descriptions only when requested", async () => {
    vi.mocked(mockClient.getManagerLogs!).mockResolvedValue({
      data: {
        affected_items: [
          {
            timestamp: "2026-01-15T10:00:00Z",
            tag: "wazuh-modulesd",
            level: "info",
            description: "sensitive host log line",
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_manager_logs")!;
    const result = await handler({
      limit: 10,
      offset: 0,
      include_description: true,
    });
    const data = parseToolResult(result) as Record<string, unknown>;
    const logs = data.logs as Array<Record<string, unknown>>;

    expect(logs[0].description).toBe("sensitive host log line");
  });

  it("should redact sensitive manager config values by default", async () => {
    vi.mocked(mockClient.getManagerConfig!).mockResolvedValue({
      data: {
        auth: {
          token: "manager-token",
          nested: {
            password: "manager-password",
          },
        },
        global: {
          email_notification: "yes",
        },
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_manager_config")!;
    const result = await handler({ section: "auth" });
    const text = result.content[0].text;
    const data = parseToolResult(result) as Record<string, unknown>;

    expect(text).not.toContain("manager-token");
    expect(text).not.toContain("manager-password");
    expect(text).toContain("[REDACTED]");
    expect((data.output as Record<string, unknown>).sensitive_config_included).toBe(false);
  });

  it("should include sensitive manager config only when the server allows it and it is requested", async () => {
    vi.stubEnv("WAZUH_ALLOW_SENSITIVE_CONFIG", "true");
    vi.mocked(mockClient.getManagerConfig!).mockResolvedValue({
      data: {
        auth: {
          token: "manager-token",
        },
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_manager_config")!;
    const result = await handler({ section: "auth", include_sensitive_config: true });
    const text = result.content[0].text;
    const data = parseToolResult(result) as Record<string, unknown>;

    expect(text).toContain("manager-token");
    expect((data.output as Record<string, unknown>).sensitive_config_included).toBe(true);
  });

  it("should always redact when the server flag is off, even if the model requests sensitive config", async () => {
    // WAZUH_ALLOW_SENSITIVE_CONFIG unset (default off): a model-supplied
    // include_sensitive_config must NOT bypass redaction.
    vi.mocked(mockClient.getManagerConfig!).mockResolvedValue({
      data: {
        auth: {
          token: "manager-token",
        },
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_manager_config")!;
    const result = await handler({ section: "auth", include_sensitive_config: true });
    const text = result.content[0].text;
    const data = parseToolResult(result) as Record<string, unknown>;

    expect(text).not.toContain("manager-token");
    expect(text).toContain("[REDACTED]");
    expect((data.output as Record<string, unknown>).sensitive_config_included).toBe(false);
  });
});

describe("Syscollector Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getAgentProcesses: vi.fn(),
    };
    tools = captureTools(registerSyscollectorTools, mockClient);
  });

  it("should omit process command lines by default", async () => {
    vi.mocked(mockClient.getAgentProcesses!).mockResolvedValue({
      data: {
        affected_items: [
          {
            pid: 123,
            name: "bash",
            cmd: "/bin/bash -lc secret",
            argvs: ["bash", "-lc", "secret"],
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_agent_processes")!;
    const result = await handler({ agent_id: "001", limit: 10, offset: 0 });
    const data = parseToolResult(result) as Record<string, unknown>;
    const processes = data.processes as Array<Record<string, unknown>>;

    expect(processes[0].cmd).toBeUndefined();
    expect(processes[0].argvs).toBeUndefined();
    expect((data.output as Record<string, unknown>).command_included).toBe(false);
  });

  it("should include process command lines only when requested", async () => {
    vi.mocked(mockClient.getAgentProcesses!).mockResolvedValue({
      data: {
        affected_items: [
          {
            pid: 123,
            name: "bash",
            cmd: "/bin/bash -lc secret",
            argvs: ["bash", "-lc", "secret"],
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_agent_processes")!;
    const result = await handler({
      agent_id: "001",
      limit: 10,
      offset: 0,
      include_command: true,
    });
    const data = parseToolResult(result) as Record<string, unknown>;
    const processes = data.processes as Array<Record<string, unknown>>;

    expect(processes[0].cmd).toBe("/bin/bash -lc secret");
    expect(processes[0].argvs).toEqual(["bash", "-lc", "secret"]);
  });
});

describe("Syscheck Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getFimFiles: vi.fn(),
    };
    tools = captureTools(registerSyscheckTools, mockClient);
  });

  it("should omit FIM hashes by default", async () => {
    vi.mocked(mockClient.getFimFiles!).mockResolvedValue({
      data: {
        affected_items: [
          {
            file: "/etc/passwd",
            type: "file",
            md5: "md5-value",
            sha256: "sha256-value",
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_fim_files")!;
    const result = await handler({ agent_id: "001", limit: 10, offset: 0 });
    const data = parseToolResult(result) as Record<string, unknown>;
    const files = data.files as Array<Record<string, unknown>>;

    expect(files[0].md5).toBeUndefined();
    expect(files[0].sha256).toBeUndefined();
    expect((data.output as Record<string, unknown>).hashes_included).toBe(false);
  });

  it("should include FIM hashes only when requested", async () => {
    vi.mocked(mockClient.getFimFiles!).mockResolvedValue({
      data: {
        affected_items: [
          {
            file: "/etc/passwd",
            type: "file",
            md5: "md5-value",
            sha256: "sha256-value",
          },
        ],
        total_affected_items: 1,
        failed_items: [],
        total_failed_items: 0,
      },
      error: 0,
      message: "ok",
    });

    const handler = tools.get("get_fim_files")!;
    const result = await handler({
      agent_id: "001",
      limit: 10,
      offset: 0,
      include_hashes: true,
    });
    const data = parseToolResult(result) as Record<string, unknown>;
    const files = data.files as Array<Record<string, unknown>>;

    expect(files[0].md5).toBe("md5-value");
    expect(files[0].sha256).toBe("sha256-value");
  });
});

describe("Version Tools", () => {
  let mockClient: Partial<WazuhClient>;
  let tools: Map<string, ToolHandler>;

  beforeEach(() => {
    mockClient = {
      getVersion: vi.fn(),
    };
    tools = captureTools(registerVersionTools, mockClient);
  });

  describe("get_wazuh_version", () => {
    it("should return version info", async () => {
      vi.mocked(mockClient.getVersion!).mockResolvedValue({
        data: {
          title: "Wazuh API REST",
          api_version: "4.7.0",
          revision: 40700,
          license_name: "GPL 2.0",
          license_url: "https://github.com/wazuh/wazuh/blob/master/LICENSE",
          hostname: "wazuh-manager",
          timestamp: "2026-01-15T10:00:00Z",
        },
        error: 0,
        message: "ok",
      });

      const handler = tools.get("get_wazuh_version")!;
      const result = await handler({});
      const data = parseToolResult(result) as Record<string, unknown>;

      expect(data.api_version).toBe("4.7.0");
      expect(data.hostname).toBe("wazuh-manager");
      expect(data.license).toBe("GPL 2.0");
    });

    it("should handle connection errors", async () => {
      vi.mocked(mockClient.getVersion!).mockRejectedValue(
        new Error("ECONNREFUSED")
      );

      const handler = tools.get("get_wazuh_version")!;
      const result = await handler({});

      expect(result.isError).toBe(true);
      const data = parseToolResult(result) as Record<string, unknown>;
      expect(data.error).toBe("ECONNREFUSED");
    });
  });
});
