import { beforeEach, describe, expect, it, vi } from "vitest";
import { WazuhClient } from "../src/client.js";
import { httpRequest, type HttpResponse } from "../src/http.js";
import { WazuhIndexerClient } from "../src/indexer-client.js";

vi.mock("../src/http.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/http.js")>();
  return { ...actual, httpRequest: vi.fn() };
});

const requestSpy = vi.mocked(httpRequest);

function mockResponse(body: unknown): HttpResponse {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  };
}

describe("TLS servername wiring", () => {
  beforeEach(() => {
    requestSpy.mockReset();
  });

  it("passes each client's own servername to httpRequest", async () => {
    requestSpy.mockResolvedValue(mockResponse({ data: { token: "t" } }));
    await new WazuhClient({
      url: "https://192.0.2.10:55000",
      username: "admin",
      password: "secret",
      verifySsl: true,
      timeout: 1000,
      tlsServername: "localhost",
    }).authenticate();
    requestSpy.mockResolvedValue(mockResponse({ cluster_name: "c" }));
    await new WazuhIndexerClient({
      url: "https://192.0.2.11:9200",
      username: "reader",
      password: "secret",
      verifySsl: true,
      timeout: 1000,
      tlsServername: "127.0.0.1",
    }).getInfo();

    expect(requestSpy.mock.calls[0][1].tlsServername).toBe("localhost");
    expect(requestSpy.mock.calls[1][1].tlsServername).toBe("127.0.0.1");
  });

  it("leaves the servername undefined when not configured", async () => {
    requestSpy.mockResolvedValue(mockResponse({ cluster_name: "c" }));
    await new WazuhIndexerClient({
      url: "https://192.0.2.11:9200",
      username: "reader",
      password: "secret",
      verifySsl: true,
      timeout: 1000,
    }).getInfo();
    expect(requestSpy.mock.calls[0][1].tlsServername).toBeUndefined();
  });
});
