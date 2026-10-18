import { randomUUID } from "node:crypto";
import { request } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createHttpServer, type HttpServerHandle } from "../src/mcp-http.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { stripSchemaFromToolList } from "../src/mcp-server.js";
import { httpRequest, type HttpResponse } from "../src/http.js";

vi.mock("../src/http.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/http.js")>(),
  httpRequest: vi.fn(),
}));

const TOKEN = randomUUID();
const env = {
  WAZUH_URL: "https://wazuh.example.com",
  WAZUH_USERNAME: "test-reader-".repeat(3),
  WAZUH_PASSWORD: "test-upstream-secret-".repeat(2),
  WAZUH_MCP_HTTP_TOKEN: TOKEN,
  WAZUH_MCP_HTTP_PORT: "0",
  WAZUH_MCP_HTTP_HOST: undefined,
  WAZUH_INDEXER_URL: undefined,
  WAZUH_INDEXER_USERNAME: undefined,
  WAZUH_INDEXER_PASSWORD: undefined,
};
let http: HttpServerHandle | undefined;
const connections: { client: Client; transport: StreamableHTTPClientTransport }[] = [];
afterEach(async () => {
  for (const { client, transport } of connections.splice(0)) {
    await transport.terminateSession().catch(() => undefined);
    await client.close();
  }
  await http?.close();
  http = undefined;
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function configure(extra = {}) {
  for (const [name, value] of Object.entries({ ...env, ...extra })) vi.stubEnv(name, value);
}
async function start(extra = {}) {
  configure(extra);
  http = await createHttpServer();
  return `http://localhost:${http.port}`;
}
async function connect(url: string, token = TOKEN) {
  const transport = new StreamableHTTPClientTransport(new URL(`${url}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: "http-test", version: "1" });
  connections.push({ client, transport });
  await client.connect(transport);
  return { client, transport };
}

describe("authenticated Streamable HTTP", () => {
  it("preserves the SDK send options when stripping schemas", async () => {
    const send = vi.fn<Transport["send"]>().mockResolvedValue(undefined);
    const transport: Transport = { send, start: async () => {}, close: async () => {} };
    stripSchemaFromToolList(transport);
    const notification = { jsonrpc: "2.0" as const, method: "notifications/progress", params: { progressToken: "progress", progress: 1 } };
    const options = { relatedRequestId: 42 };
    await transport.send(notification, options);
    expect(send).toHaveBeenCalledWith(notification, options);
  });

  it.each([undefined, "Bearer wrong-token"])("rejects invalid authentication: %s", async (authorization) => {
    const url = await start();
    const response = await fetch(`${url}/mcp`, { method: "POST", headers: authorization ? { authorization } : {} });
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe("Bearer");
    expect(await response.text()).toBe("Unauthorized");
  });

  it("exposes only liveness without authentication", async () => {
    const response = await fetch(`${await start()}/healthz`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("lists tools using the SDK client and terminates its session", async () => {
    const url = await start();
    const { client, transport } = await connect(url);
    const result = await client.listTools();
    expect(result.tools.length).toBeGreaterThan(0);
    expect(result.tools.some((t) => t.name === "get_wazuh_version")).toBe(true);
    for (const tool of result.tools) {
      expect(tool.inputSchema).not.toHaveProperty("$schema");
      if (tool.outputSchema) expect(tool.outputSchema).not.toHaveProperty("$schema");
    }
    const id = transport.sessionId;
    expect(id).toBeTruthy();
    await transport.terminateSession();
    const stale = await fetch(`${url}/mcp`, {
      headers: { authorization: `Bearer ${TOKEN}`, "mcp-session-id": id!, accept: "text/event-stream" },
    });
    expect(stale.status).toBe(404);
  });

  it.each([
    { origin: "https://evil.example.com" },
    { origin: "null" },
    { origin: "http://localhost.evil.example.com" },
    { host: "evil.example.com" },
    { host: "localhost@evil.example.com" },
  ])("rejects rebinding headers %j", async (headers) => {
    const url = await start();
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = request(`${url}/mcp`, { method: "POST", headers: { ...headers, authorization: `Bearer ${TOKEN}` } }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(403);
  });

  it("accepts a loopback Origin", async () => {
    const url = await start();
    const response = await fetch(`${url}/mcp`, { method: "POST", headers: { origin: url } });
    expect(response.status).toBe(401);
  });

  it.each([undefined, "", "   ", env.WAZUH_USERNAME, env.WAZUH_PASSWORD,
    Buffer.from(`${env.WAZUH_USERNAME}:${env.WAZUH_PASSWORD}`).toString("base64"),
  ])("refuses missing, blank, or reused credentials", async (token) => {
    configure({ WAZUH_MCP_HTTP_TOKEN: token });
    await expect(createHttpServer()).rejects.toThrow(/WAZUH_MCP_HTTP_TOKEN/);
  });

  it("refuses a token shorter than 32 characters", async () => {
    configure({ WAZUH_MCP_HTTP_TOKEN: "a".repeat(31) });
    await expect(createHttpServer()).rejects.toThrow(/at least 32 characters/);
  });

  it.each(["0.0.0.0", "::", "[::]"])("refuses wildcard bind host %s", async (host) => {
    configure({ WAZUH_MCP_HTTP_HOST: host });
    await expect(createHttpServer()).rejects.toThrow(/not a wildcard/);
  });

  it("accepts a token with surrounding whitespace from a secrets file", async () => {
    const { client } = await connect(await start({ WAZUH_MCP_HTTP_TOKEN: `  ${TOKEN}\n` }));
    expect((await client.listTools()).tools.some((tool) => tool.name === "get_wazuh_version")).toBe(true);
  });

  it("refuses padded upstream credentials after trimming", async () => {
    configure({ WAZUH_MCP_HTTP_TOKEN: `  ${env.WAZUH_PASSWORD}\n` });
    await expect(createHttpServer()).rejects.toThrow(/must differ from all Wazuh credentials/);
  });

  it.each(["-1", "65536", "abc", "3000suffix", "1.5"])("refuses invalid port %s", async (port) => {
    configure({ WAZUH_MCP_HTTP_PORT: port });
    await expect(createHttpServer()).rejects.toThrow(/WAZUH_MCP_HTTP_PORT/);
  });

  it("limits request bytes before JSON parsing", async () => {
    const url = await start();
    const response = await fetch(`${url}/mcp`, {
      method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: "x".repeat(1_048_577),
    });
    expect(response.status).toBe(413);
  });

  it("limits chunked bodies without a Content-Length", async () => {
    const url = await start();
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = request(`${url}/mcp`, {
        method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      req.on("error", reject);
      req.write("x".repeat(600_000));
      req.end("x".repeat(600_000));
    });
    expect(status).toBe(413);
  });

  it("expires idle sessions even with an SSE channel open", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const url = await start();
    const { transport } = await connect(url);
    const id = transport.sessionId!;
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 31 * 60_000);
    await vi.advanceTimersByTimeAsync(60_000);
    const response = await fetch(`${url}/mcp`, {
      headers: { authorization: `Bearer ${TOKEN}`, "mcp-session-id": id, accept: "text/event-stream" },
    });
    expect(response.status).toBe(404);
  });

  it("shares JWT login and refresh while keeping session lifecycles independent", async () => {
    let authCount = 0;
    let expire = false;
    vi.mocked(httpRequest).mockImplementation(async (url, options) => {
      let status = 200;
      let body: unknown;
      if (url.endsWith("/security/user/authenticate")) {
        authCount++;
        await new Promise((resolve) => setTimeout(resolve, 10));
        body = { data: { token: `test-token-${authCount}` } };
      } else if (expire && options.headers?.Authorization === "Bearer test-token-1") {
        status = 401;
        body = {};
      } else {
        body = { data: { title: "Wazuh", api_version: "4.14.0" } };
      }
      return {
        ok: status === 200, status, statusText: status === 200 ? "OK" : "Unauthorized",
        json: async () => body, text: async () => JSON.stringify(body),
      } satisfies HttpResponse;
    });
    const url = await start();
    const [a, b] = await Promise.all([connect(url), connect(url)]);
    expect(a.transport.sessionId).not.toBe(b.transport.sessionId);
    const call = (client: Client) => client.callTool({ name: "get_wazuh_version", arguments: {} });
    const first = await Promise.all([call(a.client), call(b.client)]);
    expect(first.every((result) => !result.isError)).toBe(true);
    expect(authCount).toBe(1);
    expire = true;
    const refreshed = await Promise.all([call(a.client), call(b.client)]);
    expect(refreshed.every((result) => !result.isError)).toBe(true);
    expect(authCount).toBe(2);
    await a.transport.terminateSession();
    expect((await b.client.listTools()).tools.some((tool) => tool.name === "get_wazuh_version")).toBe(true);
    expect((await call(b.client)).isError).not.toBe(true);
    expect(authCount).toBe(2);
  });

  it.each(["indexer-reader-".repeat(3), "indexer-secret-".repeat(3)])("refuses indexer credential reuse: %s", async (token) => {
    configure({
      WAZUH_INDEXER_URL: "https://indexer.example.com",
      WAZUH_INDEXER_USERNAME: "indexer-reader-".repeat(3), WAZUH_INDEXER_PASSWORD: "indexer-secret-".repeat(3),
      WAZUH_MCP_HTTP_TOKEN: token,
    });
    await expect(createHttpServer()).rejects.toThrow(/WAZUH_MCP_HTTP_TOKEN/);
  });

  it("redacts the trimmed HTTP credential from tool errors", async () => {
    const token = randomUUID();
    vi.mocked(httpRequest).mockRejectedValue(new Error(`upstream echoed ${token}`));
    const { client } = await connect(await start({ WAZUH_MCP_HTTP_TOKEN: `  ${token}\n` }), token);
    const result = await client.callTool({ name: "get_wazuh_version", arguments: {} });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain("[REDACTED]");
    expect(JSON.stringify(result)).not.toContain(token);
  });

  it("caps initialized sessions and releases capacity on deletion", async () => {
    const url = await start();
    const initialize = () => fetch(`${url}/mcp`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
        protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "capacity-test", version: "1" },
      } }),
    });
    const responses = await Promise.all(Array.from({ length: 128 }, initialize));
    expect(responses.every((response) => response.status === 200)).toBe(true);
    await Promise.all(responses.map((response) => response.text()));
    const full = await initialize();
    expect(full.status).toBe(503);
    await full.text();
    const deleted = await fetch(`${url}/mcp`, {
      method: "DELETE", headers: { authorization: `Bearer ${TOKEN}`, "mcp-session-id": responses[0].headers.get("mcp-session-id")! },
    });
    expect(deleted.status).toBe(200);
    await deleted.text();
    const available = await initialize();
    expect(available.status).toBe(200);
    await available.text();
  });

  it("closes active sessions and the listener idempotently", async () => {
    const url = await start();
    await connect(url);
    await Promise.all([http!.close(), http!.close()]);
    await expect(fetch(`${url}/healthz`)).rejects.toThrow();
  });
});
