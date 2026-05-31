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
