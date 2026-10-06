import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HELP, isEntryPoint, parseArgs, run, type WazuhCtrlDeps } from "../src/cli.js";
import type { WazuhClient } from "../src/client.js";
import type { WazuhConfig } from "../src/config.js";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
) as { version: string; bin?: Record<string, string> };

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
      wazuhctrl: "dist/cli.js",
      wazuhctl: "dist/cli.js",
      "wazuh-mcp": "dist/mcp-bin.js",
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

  it("reports a wazuhctrl mcp startup error as JSON and exits 1", async () => {
    const serve = vi
      .fn()
      .mockRejectedValue(
        new Error("WAZUH_INDEXER_USERNAME environment variable is required when WAZUH_INDEXER_URL is set.")
      );
    const { out, err, deps } = capture({}, { serve });

    await expect(run(["mcp"], deps)).resolves.toBe(1);

    expect(serve).toHaveBeenCalledTimes(1);
    expect(out).toEqual([]);
    expect(err).toHaveLength(1);
    expect(JSON.parse(err[0])).toEqual({
      error: "WAZUH_INDEXER_USERNAME environment variable is required when WAZUH_INDEXER_URL is set.",
    });
  });
});

// npm runs bins (npx, global installs, node_modules/.bin) through a symlink, so
// process.argv[1] is the link while import.meta.url is the real file.
describe("wazuhctrl entry-point detection", () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  function tempDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "wazuhctrl-entry-"));
    dirs.push(dir);
    return dir;
  }

  it("treats a symlink to the module file as the entry point", () => {
    const dir = tempDir();
    const moduleFile = join(dir, "cli.js");
    const binLink = join(dir, "wazuhctrl");
    writeFileSync(moduleFile, "");
    symlinkSync(moduleFile, binLink);

    expect(isEntryPoint(binLink, pathToFileURL(moduleFile).href)).toBe(true);
    expect(isEntryPoint(moduleFile, pathToFileURL(moduleFile).href)).toBe(true);
  });

  it("rejects an unrelated script, a dangling path, and a missing argv[1]", () => {
    const dir = tempDir();
    const moduleFile = join(dir, "cli.js");
    const otherFile = join(dir, "other.js");
    writeFileSync(moduleFile, "");
    writeFileSync(otherFile, "");
    const moduleUrl = pathToFileURL(moduleFile).href;

    expect(isEntryPoint(otherFile, moduleUrl)).toBe(false);
    expect(isEntryPoint(join(dir, "missing.js"), moduleUrl)).toBe(false);
    expect(isEntryPoint(undefined, moduleUrl)).toBe(false);
  });

  const cliUrl = new URL("../src/cli.ts", import.meta.url);

  function binSymlinkToCli(): string {
    const binDir = join(tempDir(), "node_modules", ".bin");
    mkdirSync(binDir, { recursive: true });
    const binLink = join(binDir, "wazuhctrl");
    symlinkSync(fileURLToPath(cliUrl), binLink);
    return binLink;
  }

  function spawnNode(args: string[]) {
    return spawnSync(process.execPath, ["--import", "tsx", ...args], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      encoding: "utf8",
      timeout: 30_000,
    });
  }

  function expectVersionPrinted(result: ReturnType<typeof spawnNode>): void {
    expect(result.error).toBeUndefined();
    expect({ status: result.status, stdout: result.stdout.trim() }, result.stderr).toEqual({
      status: 0,
      stdout: packageJson.version,
    });
  }

  // Runs the module-level entry guard itself, which the helper tests above do
  // not reach. 2.0.0 printed nothing and exited 0 here. No network calls.
  it("runs the CLI when started through an npm-style bin symlink", () => {
    expectVersionPrinted(spawnNode([binSymlinkToCli(), "--version"]));
  }, 30_000);

  // On Node 22.18+ and 24.2+ the test above passes on import.meta.main alone.
  // Importing the CLI from an inline module keeps import.meta.main false while
  // argv[1] is still the bin symlink, which is what older Node releases see,
  // so this run only succeeds through the realpath fallback in the guard.
  it("runs the CLI through the realpath fallback when import.meta.main is false", () => {
    const binLink = binSymlinkToCli();
    const importCli = `await import(${JSON.stringify(cliUrl.href)});`;
    expectVersionPrinted(spawnNode(["--input-type=module", "-e", importCli, binLink, "--version"]));
  }, 30_000);

  // Guards the extensionless invocation, `node dist/cli`. Its argv[1] matches
  // no real file, so the realpath fallback rejects it and only import.meta.main
  // runs the CLI. Node has import.meta.main from 22.18 and 24.2, which the CI
  // Node lines include.
  const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
  const hasImportMetaMain =
    nodeMajor > 24 || (nodeMajor === 24 && nodeMinor >= 2) || (nodeMajor === 22 && nodeMinor >= 18);
  it.runIf(hasImportMetaMain)("runs the CLI when started by its path without an extension", () => {
    expectVersionPrinted(spawnNode([fileURLToPath(new URL("../src/cli", import.meta.url)), "--version"]));
  }, 30_000);
});
