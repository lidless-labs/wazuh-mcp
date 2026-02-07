import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { WazuhClient, WazuhClientError, WazuhAuthenticationError } from "../src/client.js";
import type { WazuhConfig } from "../src/config.js";

const mockConfig: WazuhConfig = {
  url: "https://wazuh.example.com:55000",
  username: "admin",
  password: "secret",
  verifySsl: false,
};

const mockToken = "eyJhbGciOiJIUzI1NiJ9.mock-jwt-token";

function mockFetchResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    headers: new Headers(),
    redirected: false,
    type: "basic",
    url: "",
    clone: () => mockFetchResponse(body, status),
    body: null,
    bodyUsed: false,
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    blob: () => Promise.resolve(new Blob()),
    formData: () => Promise.resolve(new FormData()),
    text: () => Promise.resolve(JSON.stringify(body)),
  } as Response;
}

describe("WazuhClient", () => {
  let client: WazuhClient;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    client = new WazuhClient(mockConfig);
    fetchSpy = vi.spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("authenticate", () => {
    it("should authenticate and store token", async () => {
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );

      const token = await client.authenticate();
      expect(token).toBe(mockToken);
      expect(fetchSpy).toHaveBeenCalledWith(
        "https://wazuh.example.com:55000/security/user/authenticate",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            Authorization: expect.stringContaining("Basic "),
          }),
        })
      );
    });

    it("should throw WazuhAuthenticationError on 401", async () => {
      fetchSpy.mockResolvedValueOnce(mockFetchResponse({}, 401));
      await expect(client.authenticate()).rejects.toThrow(
        WazuhAuthenticationError
      );
    });

    it("should throw WazuhAuthenticationError on missing token", async () => {
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({ data: {}, error: 0, message: "ok" })
      );
      await expect(client.authenticate()).rejects.toThrow(
        WazuhAuthenticationError
      );
    });

    it("should encode credentials as base64", async () => {
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );

      await client.authenticate();

      const expectedBase64 = Buffer.from("admin:secret").toString("base64");
      expect(fetchSpy).toHaveBeenCalledWith(
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
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: mockToken },
          error: 0,
          message: "ok",
        })
      );
    });

    it("should auto-authenticate on first request", async () => {
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      await client.get("/agents");
      // First call: auth, second call: actual request
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it("should pass query parameters", async () => {
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      await client.get("/agents", { limit: 10, status: "active" });

      const calledUrl = fetchSpy.mock.calls[1][0] as string;
      expect(calledUrl).toContain("limit=10");
      expect(calledUrl).toContain("status=active");
    });

    it("should include Bearer token in requests", async () => {
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { affected_items: [], total_affected_items: 0 },
          error: 0,
        })
      );

      await client.get("/agents");

      expect(fetchSpy.mock.calls[1][1]).toEqual(
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: `Bearer ${mockToken}`,
          }),
        })
      );
    });

    it("should retry on 401 with fresh token", async () => {
      // First API call returns 401
      fetchSpy.mockResolvedValueOnce(mockFetchResponse({}, 401));
      // Re-auth
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: "new-token" },
          error: 0,
          message: "ok",
        })
      );
      // Retry succeeds
      fetchSpy.mockResolvedValueOnce(
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
      expect(fetchSpy).toHaveBeenCalledTimes(4);
    });

    it("should throw WazuhClientError on non-401 errors", async () => {
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({ message: "Internal Server Error" }, 500)
      );

      await expect(client.get("/agents")).rejects.toThrow(WazuhClientError);
    });

    it("should throw WazuhClientError if retry also fails", async () => {
      // First call returns 401
      fetchSpy.mockResolvedValueOnce(mockFetchResponse({}, 401));
      // Re-auth succeeds
      fetchSpy.mockResolvedValueOnce(
        mockFetchResponse({
          data: { token: "new-token" },
          error: 0,
          message: "ok",
        })
      );
      // Retry also fails
      fetchSpy.mockResolvedValueOnce(mockFetchResponse({}, 403));

      await expect(client.get("/agents")).rejects.toThrow(WazuhClientError);
    });
  });

  describe("getAgents", () => {
    beforeEach(() => {
      fetchSpy.mockResolvedValueOnce(
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
              ip: "10.0.0.1",
              status: "active",
            },
            {
              id: "002",
              name: "agent-2",
              ip: "10.0.0.2",
              status: "disconnected",
            },
          ],
          total_affected_items: 2,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
      };

      fetchSpy.mockResolvedValueOnce(mockFetchResponse(mockAgents));

      const result = await client.getAgents({ limit: 10 });
      expect(result.data.affected_items).toHaveLength(2);
      expect(result.data.affected_items[0].name).toBe("agent-1");
      expect(result.data.total_affected_items).toBe(2);
    });
  });

  describe("getAgent", () => {
    beforeEach(() => {
      fetchSpy.mockResolvedValueOnce(
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
              ip: "10.0.0.1",
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

      fetchSpy.mockResolvedValueOnce(mockFetchResponse(mockAgent));

      const result = await client.getAgent("001");
      expect(result.data.affected_items[0].id).toBe("001");
      expect(result.data.affected_items[0].os?.name).toBe("Ubuntu");
    });
  });

  describe("getAlerts", () => {
    beforeEach(() => {
      fetchSpy.mockResolvedValueOnce(
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

      fetchSpy.mockResolvedValueOnce(mockFetchResponse(mockAlerts));

      const result = await client.getAlerts({ limit: 10 });
      expect(result.data.affected_items).toHaveLength(1);
      expect(result.data.affected_items[0].rule?.id).toBe("5710");
    });
  });

  describe("getRules", () => {
    beforeEach(() => {
      fetchSpy.mockResolvedValueOnce(
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

      fetchSpy.mockResolvedValueOnce(mockFetchResponse(mockRules));

      const result = await client.getRules({ limit: 10 });
      expect(result.data.affected_items[0].id).toBe(5710);
      expect(result.data.affected_items[0].mitre?.technique).toContain(
        "Brute Force"
      );
    });
  });

  describe("getRule", () => {
    beforeEach(() => {
      fetchSpy.mockResolvedValueOnce(
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

      fetchSpy.mockResolvedValueOnce(mockFetchResponse(mockRule));

      const result = await client.getRule(5710);
      expect(result.data.affected_items[0].id).toBe(5710);
    });
  });

  describe("getDecoders", () => {
    beforeEach(() => {
      fetchSpy.mockResolvedValueOnce(
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

      fetchSpy.mockResolvedValueOnce(mockFetchResponse(mockDecoders));

      const result = await client.getDecoders({ limit: 10 });
      expect(result.data.affected_items).toHaveLength(2);
      expect(result.data.affected_items[0].name).toBe("sshd");
    });
  });

  describe("getVersion", () => {
    beforeEach(() => {
      fetchSpy.mockResolvedValueOnce(
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

      fetchSpy.mockResolvedValueOnce(mockFetchResponse(mockVersion));

      const result = await client.getVersion();
      expect(result.data.api_version).toBe("4.7.0");
      expect(result.data.hostname).toBe("wazuh-manager");
    });
  });
});
