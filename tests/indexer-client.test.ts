import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WazuhIndexerClient } from "../src/indexer-client.js";

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

describe("WazuhIndexerClient", () => {
  let client: WazuhIndexerClient;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    client = new WazuhIndexerClient({
      url: "https://indexer.example.com:9200",
      username: "admin",
      password: "secret",
      verifySsl: false,
    });
    fetchSpy = vi.spyOn(globalThis, "fetch");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should sort alert searches by descending timestamp by default", async () => {
    fetchSpy.mockResolvedValueOnce(
      mockFetchResponse({ hits: { total: { value: 0, relation: "eq" }, hits: [] } })
    );

    await client.searchAlerts({ match_all: {} }, 10, 0);

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string) as Record<
      string,
      unknown
    >;
    expect(requestBody.sort).toEqual([{ timestamp: { order: "desc" } }]);
    expect(requestBody.track_total_hits).toBe(true);
  });

  it("should support ascending timestamp sort for recent alerts", async () => {
    fetchSpy.mockResolvedValueOnce(
      mockFetchResponse({ hits: { total: { value: 0, relation: "eq" }, hits: [] } })
    );

    await client.getRecentAlerts(10, 0, { sortOrder: "asc" });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string) as Record<
      string,
      unknown
    >;
    expect(requestBody.sort).toEqual([{ timestamp: { order: "asc" } }]);
  });

  it("should add alert timestamp range filters", async () => {
    fetchSpy.mockResolvedValueOnce(
      mockFetchResponse({ hits: { total: { value: 0, relation: "eq" }, hits: [] } })
    );

    await client.getRecentAlerts(10, 0, {
      start_time: "2026-01-01T00:00:00.000Z",
      end_time: "2026-01-02T00:00:00.000Z",
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string) as {
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
    fetchSpy.mockResolvedValueOnce(
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

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string) as {
      query: { bool: { must: unknown[] } };
      sort: unknown;
      track_total_hits?: boolean;
    };
    expect(fetchSpy.mock.calls[0][0]).toBe(
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
    fetchSpy.mockResolvedValueOnce(
      mockFetchResponse({ cluster_name: "wazuh-indexer", version: { number: "2.11.0" } })
    );

    const info = await client.getInfo();

    expect(info.cluster_name).toBe("wazuh-indexer");
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://indexer.example.com:9200/",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: expect.stringContaining("Basic "),
        }),
      })
    );
  });
});
