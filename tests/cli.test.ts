import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { HELP, parseArgs, run, type WazuhCtrlDeps } from "../src/cli.js";
import type { WazuhClient } from "../src/client.js";
import type { WazuhConfig } from "../src/config.js";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
) as { bin?: Record<string, string> };

const mockConfig: WazuhConfig = {
  url: "https://wazuh.example.com:55000",
  username: "wazuh",
  password: "secret",
  verifySsl: true,
  timeout: 30_000,
};

function capture(client: Partial<WazuhClient>, deps: Partial<WazuhCtrlDeps> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const resolvedDeps: Partial<WazuhCtrlDeps> = {
    out: (text) => out.push(text),
    err: (text) => err.push(text),
    getConfig: () => mockConfig,
    makeClient: () => client as WazuhClient,
    makeIndexerClient: vi.fn(),
    serve: vi.fn().mockResolvedValue(undefined),
    ...deps,
  };
  return { out, err, deps: resolvedDeps };
}

describe("wazuhctrl CLI", () => {
  it("documents wazuhctrl as the primary CLI and keeps compatibility bins", () => {
    expect(HELP).toContain("wazuhctrl - read-only Wazuh SIEM/XDR control CLI");
    expect(HELP).toContain("alias: wazuhctl");
    expect(packageJson.bin).toMatchObject({
      wazuhctrl: "./dist/cli.js",
      wazuhctl: "./dist/cli.js",
      "wazuh-mcp": "./dist/mcp-bin.js",
    });
  });

  it("parses the first-slice commands", () => {
    expect(parseArgs(["status", "--json"])).toEqual({ kind: "status", json: true });
    expect(parseArgs(["agents", "list", "--limit", "20"])).toMatchObject({
      kind: "agents list",
      limit: 20,
      offset: 0,
    });
    expect(parseArgs(["diagnostics", "--no-connectivity"])).toEqual({
      kind: "diagnostics",
      json: false,
      checkConnectivity: false,
    });
  });

  it("runs wazuhctrl status --json", async () => {
    const client = {
      getVersion: vi.fn().mockResolvedValue({
        data: {
          title: "Wazuh API REST",
          api_version: "4.8.0",
          revision: 4800,
          license_name: "GPLv2",
          hostname: "manager-1",
          timestamp: "2026-07-06T03:00:00Z",
        },
        error: 0,
        message: "ok",
      }),
    };
    const { out, deps } = capture(client);

    await expect(run(["status", "--json"], deps)).resolves.toBe(0);

    const data = JSON.parse(out[0]) as Record<string, any>;
    expect(data.status).toBe("ok");
    expect(data.manager.api_version).toBe("4.8.0");
    expect(client.getVersion).toHaveBeenCalledTimes(1);
  });

  it("runs wazuhctrl agents list --limit 20 without exposing IPs by default", async () => {
    const client = {
      getAgents: vi.fn().mockResolvedValue({
        data: {
          affected_items: [
            {
              id: "001",
              name: "server-1",
              ip: "192.0.2.10",
              status: "active",
              group: ["default"],
              os: { name: "Ubuntu", version: "24.04", platform: "linux" },
              version: "Wazuh v4.8.0",
              manager: "manager-1",
              node_name: "node01",
              dateAdd: "2026-07-01T00:00:00Z",
              lastKeepAlive: "2026-07-06T03:00:00Z",
            },
          ],
          total_affected_items: 1,
          failed_items: [],
          total_failed_items: 0,
        },
        error: 0,
        message: "ok",
      }),
    };
    const { out, deps } = capture(client);

    await expect(run(["agents", "list", "--limit", "20"], deps)).resolves.toBe(0);

    expect(client.getAgents).toHaveBeenCalledWith({ limit: 20, offset: 0 });
    expect(out.join("\n")).toContain("agents total=1 limit=20 offset=0");
    expect(out.join("\n")).toContain("id=001 name=server-1 status=active");
    expect(out.join("\n")).not.toContain("192.0.2.10");
  });

  it("runs wazuhctrl diagnostics with missing indexer as a warning", async () => {
    const client = {
      authenticate: vi.fn(),
      getVersion: vi.fn(),
    };
    const { out, deps } = capture(client);

    await expect(run(["diagnostics", "--no-connectivity"], deps)).resolves.toBe(0);

    expect(client.authenticate).not.toHaveBeenCalled();
    expect(out.join("\n")).toContain("diagnostics status=warning");
    expect(out.join("\n")).toContain("WAZUH_INDEXER_URL is not configured");
  });

  it("delegates wazuhctrl mcp to the MCP server", async () => {
    const serve = vi.fn().mockResolvedValue(undefined);
    const { deps } = capture({}, { serve });

    await expect(run(["mcp"], deps)).resolves.toBe(0);

    expect(serve).toHaveBeenCalledTimes(1);
  });
});
