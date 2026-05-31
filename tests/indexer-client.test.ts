import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WazuhIndexerClient } from "../src/indexer-client.js";
import { httpRequest, type HttpResponse } from "../src/http.js";

vi.mock("../src/http.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/http.js")>();
  return {
    ...actual,
    httpRequest: vi.fn(),
  };
});

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

describe("WazuhIndexerClient", () => {
  let client: WazuhIndexerClient;

  beforeEach(() => {
    requestSpy.mockReset();
    client = new WazuhIndexerClient({
      url: "https://indexer.example.com:9200",
      username: "admin",
      password: "secret",
      verifySsl: false,
      timeout: 30000,
    });
  });

  afterEach(() => {
    requestSpy.mockReset();
  });

  it("should sort alert searches by descending timestamp by default", async () => {
    requestSpy.mockResolvedValueOnce(
      mockFetchResponse({ hits: { total: { value: 0, relation: "eq" }, hits: [] } })
    );

    await client.searchAlerts({ match_all: {} }, 10, 0);

    const requestBody = JSON.parse(requestSpy.mock.calls[0][1]?.body as string) as Record<
      string,
      unknown
    >;
    expect(requestBody.sort).toEqual([{ timestamp: { order: "desc" } }]);
    expect(requestBody.track_total_hits).toBe(true);
  });

  it("should support ascending timestamp sort for recent alerts", async () => {
    requestSpy.mockResolvedValueOnce(
      mockFetchResponse({ hits: { total: { value: 0, relation: "eq" }, hits: [] } })
    );

    await client.getRecentAlerts(10, 0, { sortOrder: "asc" });

    const requestBody = JSON.parse(requestSpy.mock.calls[0][1]?.body as string) as Record<
      string,
      unknown
    >;
    expect(requestBody.sort).toEqual([{ timestamp: { order: "asc" } }]);
  });

  it("should add alert timestamp range filters", async () => {
    requestSpy.mockResolvedValueOnce(
      mockFetchResponse({ hits: { total: { value: 0, relation: "eq" }, hits: [] } })
    );

    await client.getRecentAlerts(10, 0, {
      start_time: "2026-01-01T00:00:00.000Z",
      end_time: "2026-01-02T00:00:00.000Z",
    });

    const requestBody = JSON.parse(requestSpy.mock.calls[0][1]?.body as string) as {
      query: { bool: { must: unknown[] } };
    };
    expect(requestBody.query.bool.must).toContainEqual({
      range: {
        timestamp: {
          gte: "2026-01-01T00:00:00.000Z",
          lte: "2026-01-02T00:00:00.000Z",
        },
      },
    });
  });

  it("should query vulnerability inventory with filters", async () => {
    requestSpy.mockResolvedValueOnce(
      mockFetchResponse({
        hits: {
          total: { value: 1, relation: "eq" },
          hits: [
            {
              _id: "001_package_CVE-2020-14393",
              _index: "wazuh-states-vulnerabilities-test",
              _source: {
                agent: { id: "001", name: "server-1", version: "v4.9.1" },
                package: { name: "perl-DBI", version: "1.627-4.el7", type: "rpm" },
                vulnerability: {
                  id: "CVE-2020-14393",
                  severity: "Low",
                  detected_at: "2024-12-11T00:14:31.360Z",
                  score: { base: 3.6, version: "2.0" },
                },
              },
            },
          ],
        },
      })
    );

    const result = await client.searchVulnerabilities(10, 0, {
      cve_id: "CVE-2020-14393",
      agent_id: "001",
      severity: "Low",
    });

    const requestBody = JSON.parse(requestSpy.mock.calls[0][1]?.body as string) as {
      query: { bool: { must: unknown[] } };
      sort: unknown;
      track_total_hits?: boolean;
    };
    expect(requestSpy.mock.calls[0][0]).toBe(
      "https://indexer.example.com:9200/wazuh-states-vulnerabilities*/_search"
    );
    expect(requestBody.query.bool.must).toContainEqual({
      term: { "vulnerability.id": "CVE-2020-14393" },
    });
    expect(requestBody.query.bool.must).toContainEqual({ term: { "agent.id": "001" } });
    expect(requestBody.query.bool.must).toContainEqual({
      term: { "vulnerability.severity": "Low" },
    });
    expect(requestBody.track_total_hits).toBe(true);
    expect(result.total).toBe(1);
    expect(result.vulnerabilities[0].vulnerability?.id).toBe("CVE-2020-14393");
    expect(result.vulnerabilities[0].package?.name).toBe("perl-DBI");
  });

  it("should fetch indexer info for diagnostics", async () => {
    requestSpy.mockResolvedValueOnce(
      mockFetchResponse({ cluster_name: "wazuh-indexer", version: { number: "2.11.0" } })
    );

    const info = await client.getInfo();

    expect(info.cluster_name).toBe("wazuh-indexer");
    expect(requestSpy).toHaveBeenCalledWith(
      "https://indexer.example.com:9200/",
      expect.objectContaining({
        method: "GET",
        timeoutMs: 30000,
        verifySsl: false,
        headers: expect.objectContaining({
          Authorization: expect.stringContaining("Basic "),
        }),
      })
    );
  });

  it("should check index readiness for diagnostics", async () => {
    requestSpy.mockResolvedValueOnce(mockFetchResponse(null));

    const exists = await client.indexExists("wazuh-states-vulnerabilities*");

    expect(exists).toBe(true);
    expect(requestSpy).toHaveBeenCalledWith(
      "https://indexer.example.com:9200/wazuh-states-vulnerabilities*",
      expect.objectContaining({
        method: "HEAD",
        headers: expect.objectContaining({
          Authorization: expect.stringContaining("Basic "),
        }),
      })
    );
  });

  it("should return false when an index is missing", async () => {
    requestSpy.mockResolvedValueOnce(mockFetchResponse(null, 404));

    await expect(client.indexExists("missing-index*")).resolves.toBe(false);
  });

  it("should retry transient indexer search failures", async () => {
    requestSpy.mockResolvedValueOnce(mockFetchResponse({ error: { type: "busy" } }, 503));
    requestSpy.mockResolvedValueOnce(
      mockFetchResponse({ hits: { total: { value: 0, relation: "eq" }, hits: [] } })
    );

    const result = await client.searchAlerts({ match_all: {} }, 10, 0);

    expect(result.total).toBe(0);
    expect(requestSpy).toHaveBeenCalledTimes(2);
  });
});
