import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { WazuhClient, WazuhClientError, WazuhAuthenticationError } from "../src/client.js";
import type { WazuhConfig } from "../src/config.js";
import { httpRequest, type HttpResponse } from "../src/http.js";

vi.mock("../src/http.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/http.js")>();
  return {
    ...actual,
    httpRequest: vi.fn(),
  };
});

const mockConfig: WazuhConfig = {
  url: "https://wazuh.example.com:55000",
  username: "admin",
  password: "secret",
  verifySsl: false,
  timeout: 30000,
};

const mockToken = "eyJhbGciOiJIUzI1NiJ9.mock-jwt-token";

const requestSpy = vi.mocked(httpRequest);

function mockFetchResponse(body: unknown, status = 200): HttpResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  };
}

describe("WazuhClient", () => {
  let client: WazuhClient;

  beforeEach(() => {
    requestSpy.mockReset();
    client = new WazuhClient(mockConfig);
  });

  afterEach(() => {
    requestSpy.mockReset();
  });

  describe("authenticate", () => {
    it("should authenticate and store token", async () => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );

      const token = await client.authenticate();
      expect(token).toBe(mockToken);
      expect(requestSpy).toHaveBeenCalledWith(
        "https://wazuh.example.com:55000/security/user/authenticate",
        expect.objectContaining({
          method: "POST",
          timeoutMs: 30000,
          verifySsl: false,
          headers: expect.objectContaining({
            Authorization: expect.stringContaining("Basic "),
          }),
        })
      );
    });

    it("should throw WazuhAuthenticationError on 401", async () => {
      requestSpy.mockResolvedValueOnce(mockFetchResponse({}, 401));
      await expect(client.authenticate()).rejects.toThrow(
        WazuhAuthenticationError
      );
    });

    it("should throw WazuhAuthenticationError on missing token", async () => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({ data: {}, error: 0, message: "ok" })
      );
      await expect(client.authenticate()).rejects.toThrow(
        WazuhAuthenticationError
      );
    });

    it("should encode credentials as base64", async () => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );

      await client.authenticate();

      const expectedBase64 = Buffer.from("admin:secret").toString("base64");
      expect(requestSpy).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: `Basic ${expectedBase64}`,
          }),
        })
      );
    });
  });

  describe("request", () => {
    beforeEach(() => {
      // First call is always auth
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should auto-authenticate on first request", async () => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      await client.get("/agents");
      // First call: auth, second call: actual request
      expect(requestSpy).toHaveBeenCalledTimes(2);
    });

    it("should pass query parameters", async () => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      await client.get("/agents", { limit: 10, status: "active" });

      const calledUrl = requestSpy.mock.calls[1][0] as string;
      expect(calledUrl).toContain("limit=10");
      expect(calledUrl).toContain("status=active");
    });

    it("should include Bearer token in requests", async () => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      await client.get("/agents");

      expect(requestSpy.mock.calls[1][1]).toEqual(
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: `Bearer ${mockToken}`,
          }),
        })
      );
    });

    it("should retry on 401 with fresh token", async () => {
      // First API call returns 401
      requestSpy.mockResolvedValueOnce(mockFetchResponse({}, 401));
      // Re-auth
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: "new-token" },
          error: 0,
          message: "ok",
        })
      );
      // Retry succeeds
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      const result = await client.get("/agents");
      expect(result).toEqual({
        data: { affected_items: [], total_affected_items: 0 },
        error: 0,
      });
      // auth + first try + re-auth + retry = 4 calls
      expect(requestSpy).toHaveBeenCalledTimes(4);
    });

    it("should throw WazuhClientError on non-401 errors", async () => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse(
          {
            message:
              "Internal Server Error for password secret and bearer eyJabc.def.ghi at https://user:pass@example.com?token=abc",
          },
          500
        )
      );

      await client.get("/agents").then(
        () => {
          throw new Error("Expected request to fail");
        },
        (error: unknown) => {
          expect(error).toBeInstanceOf(WazuhClientError);
          expect((error as Error).message).not.toContain("secret");
          expect((error as Error).message).not.toContain("user:pass");
          expect((error as Error).message).not.toContain("abc");
        }
      );
    });

    it("should retry transient GET failures", async () => {
      requestSpy.mockResolvedValueOnce(mockFetchResponse({ message: "busy" }, 503));
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      const result = await client.get("/agents");

      expect(result).toEqual({
        data: { affected_items: [], total_affected_items: 0 },
        error: 0,
      });
      expect(requestSpy).toHaveBeenCalledTimes(3);
    });

    it("should throw WazuhClientError if retry also fails", async () => {
      // First call returns 401
      requestSpy.mockResolvedValueOnce(mockFetchResponse({}, 401));
      // Re-auth succeeds
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: "new-token" },
          error: 0,
          message: "ok",
        })
      );
      // Retry also fails
      requestSpy.mockResolvedValueOnce(mockFetchResponse({}, 403));

      await expect(client.get("/agents")).rejects.toThrow(WazuhClientError);
    });
  });

  describe("path segment encoding", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should encode user-controlled URL path segments", async () => {
      const agentId = "001/../../manager";
      const policyId = "cis/linux benchmark";
      const groupId = "linux/servers";
      const emptyPage = {
        data: {
          affected_items: [],
          total_affected_items: 0,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      };
      const calls: Array<[() => Promise<unknown>, string]> = [
        [
          () => client.getAgentStats(agentId),
          "https://wazuh.example.com:55000/agents/001%2F..%2F..%2Fmanager/stats/agent",
        ],
        [
          () => client.getScaPolicies(agentId),
          "https://wazuh.example.com:55000/sca/001%2F..%2F..%2Fmanager",
        ],
        [
          () => client.getScaChecks(agentId, policyId),
          "https://wazuh.example.com:55000/sca/001%2F..%2F..%2Fmanager/checks/cis%2Flinux%20benchmark",
        ],
        [
          () => client.getAgentOs(agentId),
          "https://wazuh.example.com:55000/syscollector/001%2F..%2F..%2Fmanager/os",
        ],
        [
          () => client.getAgentPackages(agentId),
          "https://wazuh.example.com:55000/syscollector/001%2F..%2F..%2Fmanager/packages",
        ],
        [
          () => client.getAgentProcesses(agentId),
          "https://wazuh.example.com:55000/syscollector/001%2F..%2F..%2Fmanager/processes",
        ],
        [
          () => client.getAgentPorts(agentId),
          "https://wazuh.example.com:55000/syscollector/001%2F..%2F..%2Fmanager/ports",
        ],
        [
          () => client.getAgentNetwork(agentId),
          "https://wazuh.example.com:55000/syscollector/001%2F..%2F..%2Fmanager/netiface",
        ],
        [
          () => client.getAgentHotfixes(agentId),
          "https://wazuh.example.com:55000/syscollector/001%2F..%2F..%2Fmanager/hotfixes",
        ],
        [
          () => client.getRootcheck(agentId),
          "https://wazuh.example.com:55000/rootcheck/001%2F..%2F..%2Fmanager",
        ],
        [
          () => client.getFimFiles(agentId),
          "https://wazuh.example.com:55000/syscheck/001%2F..%2F..%2Fmanager",
        ],
        [
          () => client.getGroupAgents(groupId),
          "https://wazuh.example.com:55000/groups/linux%2Fservers/agents",
        ],
      ];

      for (const [call, expectedUrl] of calls) {
        requestSpy.mockResolvedValueOnce(mockFetchResponse(emptyPage));
        await call();
        expect(requestSpy.mock.lastCall?.[0]).toBe(expectedUrl);
      }
    });
  });

  describe("getAgents", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should return agents list", async () => {
      const mockAgents = {
        data: {
          affected_items: [
            {
              id: "001",
              name: "agent-1",
              ip: "192.0.2.1",
              status: "active",
            },
            {
              id: "002",
              name: "agent-2",
              ip: "192.0.2.2",
              status: "disconnected",
            },
          ],
          total_affected_items: 2,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
      };

      requestSpy.mockResolvedValueOnce(mockFetchResponse(mockAgents));

      const result = await client.getAgents({ limit: 10 });
      expect(result.data.affected_items).toHaveLength(2);
      expect(result.data.affected_items[0].name).toBe("agent-1");
      expect(result.data.total_affected_items).toBe(2);
    });
  });

  describe("getAgent", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should return single agent", async () => {
      const mockAgent = {
        data: {
          affected_items: [
            {
              id: "001",
              name: "agent-1",
              ip: "192.0.2.1",
              status: "active",
              os: { name: "Ubuntu", version: "22.04", platform: "linux" },
              version: "Wazuh v4.7.0",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
      };

      requestSpy.mockResolvedValueOnce(mockFetchResponse(mockAgent));

      const result = await client.getAgent("001");
      expect(result.data.affected_items[0].id).toBe("001");
      expect(result.data.affected_items[0].os?.name).toBe("Ubuntu");
    });
  });

  describe("getAlerts", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should return alerts", async () => {
      const mockAlerts = {
        data: {
          affected_items: [
            {
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
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
      };

      requestSpy.mockResolvedValueOnce(mockFetchResponse(mockAlerts));

      const result = await client.getAlerts({ limit: 10 });
      expect(result.data.affected_items).toHaveLength(1);
      expect(result.data.affected_items[0].rule?.id).toBe("5710");
    });
  });

  describe("getRules", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should return rules", async () => {
      const mockRules = {
        data: {
          affected_items: [
            {
              id: 5710,
              description: "sshd: attempt to login using a denied user",
              level: 5,
              groups: ["sshd", "authentication_failed"],
              pci_dss: ["10.2.4", "10.2.5"],
              mitre: {
                id: ["T1110"],
                tactic: ["Credential Access"],
                technique: ["Brute Force"],
              },
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
      };

      requestSpy.mockResolvedValueOnce(mockFetchResponse(mockRules));

      const result = await client.getRules({ limit: 10 });
      expect(result.data.affected_items[0].id).toBe(5710);
      expect(result.data.affected_items[0].mitre?.technique).toContain(
        "Brute Force"
      );
    });
  });

  describe("getRule", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should return single rule", async () => {
      const mockRule = {
        data: {
          affected_items: [
            {
              id: 5710,
              description: "sshd: attempt to login using a denied user",
              level: 5,
              groups: ["sshd"],
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
      };

      requestSpy.mockResolvedValueOnce(mockFetchResponse(mockRule));

      const result = await client.getRule(5710);
      expect(result.data.affected_items[0].id).toBe(5710);
    });
  });

  describe("getDecoders", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should return decoders", async () => {
      const mockDecoders = {
        data: {
          affected_items: [
            {
              name: "sshd",
              filename: "0310-ssh_decoders.xml",
              status: "enabled",
              position: 0,
            },
            {
              name: "apache-errorlog",
              filename: "0350-apache_decoders.xml",
              status: "enabled",
              position: 0,
            },
          ],
          total_affected_items: 2,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
      };

      requestSpy.mockResolvedValueOnce(mockFetchResponse(mockDecoders));

      const result = await client.getDecoders({ limit: 10 });
      expect(result.data.affected_items).toHaveLength(2);
      expect(result.data.affected_items[0].name).toBe("sshd");
    });
  });

  describe("getVersion", () => {
    beforeEach(() => {
      requestSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should return version info", async () => {
      const mockVersion = {
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
      };

      requestSpy.mockResolvedValueOnce(mockFetchResponse(mockVersion));

      const result = await client.getVersion();
      expect(result.data.api_version).toBe("4.7.0");
      expect(result.data.hostname).toBe("wazuh-manager");
    });
  });
});
