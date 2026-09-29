import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getConfig, type IndexerConfig, type WazuhConfig } from "./config.js";
import { WazuhClient } from "./client.js";
import { WazuhIndexerClient } from "./indexer-client.js";
import { safeCaughtErrorMessage } from "./safe-error.js";
import { formatToolResponse, paginationMetadata, withOptionalField } from "./tools/output.js";
import { runWazuhDiagnostics } from "./tools/diagnostics.js";
import type { WazuhAgent } from "./types.js";
import { serveMcp } from "./mcp-server.js";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
) as { version: string };

export const HELP = `wazuhctrl - read-only Wazuh SIEM/XDR control CLI (alias: wazuhctl; MCP adapter: wazuh-mcp)

Usage:
  wazuhctrl <command> [options]

Commands:
  status [--json]                         Show Wazuh manager version and API status
  agents list [options]                   List Wazuh agents
  diagnostics [options]                   Check configuration and connectivity
  mcp                                     Start the MCP server over stdio
  help                                    Show this help
  --version                               Show package version

Agent options:
  --limit <n>                             Maximum agents to return (default: 10)
  --offset <n>                            Offset for pagination (default: 0)
  --status <status>                       active, disconnected, never_connected, or pending
  --sort <field>                          Sort field, for example -name or +id
  --include-ip                            Include agent IP addresses

Diagnostics options:
  --no-connectivity                       Skip manager and indexer network checks

Global options:
  --json                                  Emit JSON instead of a concise summary
`;

type Parsed =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "mcp" }
  | { kind: "status"; json: boolean }
  | {
      kind: "agents list";
      json: boolean;
      limit: number;
      offset: number;
      status?: string;
      sort?: string;
      includeIp: boolean;
    }
  | { kind: "diagnostics"; json: boolean; checkConnectivity: boolean };

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export interface WazuhCtrlDeps {
  out: (text: string) => void;
  err: (text: string) => void;
  getConfig: () => WazuhConfig;
  makeClient: (config: WazuhConfig) => WazuhClient;
  makeIndexerClient: (config: IndexerConfig) => WazuhIndexerClient;
  serve: () => Promise<void>;
}

const DEFAULT_DEPS: WazuhCtrlDeps = {
  out: (text) => console.log(text),
  err: (text) => console.error(text),
  getConfig,
  makeClient: (config) => new WazuhClient(config),
  makeIndexerClient: (config) => new WazuhIndexerClient(config),
  serve: serveMcp,
};

function readFlagValue(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new UsageError(`${flag} requires a value`);
  }
  return value;
}

function readInt(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new UsageError(`${flag} must be a non-negative integer`);
  }
  return parsed;
}

function stripJson(args: string[]): { args: string[]; json: boolean } {
  let json = false;
  const rest: string[] = [];
  for (const arg of args) {
    if (arg === "--json") {
      json = true;
    } else {
      rest.push(arg);
    }
  }
  return { args: rest, json };
}

export function parseArgs(rawArgs: string[]): Parsed {
  const { args, json } = stripJson(rawArgs);
  const [first, second, ...rest] = args;

  if (!first || first === "help" || first === "--help" || first === "-h") return { kind: "help" };
  if (first === "--version" || first === "version") return { kind: "version" };
  if (first === "mcp") return { kind: "mcp" };
  if (first === "status") {
    if (second) throw new UsageError(`Unknown status option: ${second}`);
    return { kind: "status", json };
  }
  if (first === "diagnostics") {
    let checkConnectivity = true;
    const options = second ? [second, ...rest] : rest;
    for (const option of options) {
      if (option === "--no-connectivity") {
        checkConnectivity = false;
      } else {
        throw new UsageError(`Unknown diagnostics option: ${option}`);
      }
    }
    return { kind: "diagnostics", json, checkConnectivity };
  }
  if (first === "agents" && second === "list") {
    let limit = 10;
    let offset = 0;
    let status: string | undefined;
    let sort: string | undefined;
    let includeIp = false;

    for (let i = 0; i < rest.length; i += 1) {
      const option = rest[i];
      if (option === "--limit") {
        limit = readInt(readFlagValue(rest, i, option), option);
        i += 1;
      } else if (option === "--offset") {
        offset = readInt(readFlagValue(rest, i, option), option);
        i += 1;
      } else if (option === "--status") {
        status = readFlagValue(rest, i, option);
        i += 1;
      } else if (option === "--sort") {
        sort = readFlagValue(rest, i, option);
        i += 1;
      } else if (option === "--include-ip") {
        includeIp = true;
      } else {
        throw new UsageError(`Unknown agents list option: ${option}`);
      }
    }

    return { kind: "agents list", json, limit, offset, status, sort, includeIp };
  }

  throw new UsageError(`Unknown command: ${args.join(" ")}`);
}

function jsonOut(value: unknown): string {
  return formatToolResponse(value);
}

function agentSummary(agent: WazuhAgent, includeIp: boolean): Record<string, unknown> {
  return withOptionalField(
    {
      id: agent.id,
      name: agent.name,
      status: agent.status,
      group: agent.group,
      os_name: agent.os?.name,
      os_version: agent.os?.version,
      os_platform: agent.os?.platform,
      version: agent.version,
      manager: agent.manager,
      node_name: agent.node_name,
      date_add: agent.dateAdd,
      last_keepalive: agent.lastKeepAlive,
    },
    "ip",
    agent.ip,
    includeIp
  );
}

async function runStatus(parsed: Extract<Parsed, { kind: "status" }>, client: WazuhClient): Promise<{ code: number; text: string }> {
  const response = await client.getVersion();
  const info = response.data;
  const result = {
    status: "ok",
    manager: {
      title: info.title,
      api_version: info.api_version,
      revision: info.revision,
      license: info.license_name,
      hostname: info.hostname,
      timestamp: info.timestamp,
    },
  };

  if (parsed.json) return { code: 0, text: jsonOut(result) };
  return {
    code: 0,
    text: [
      `status=ok title=${info.title}`,
      `api_version=${info.api_version} revision=${info.revision} hostname=${info.hostname}`,
    ].join("\n"),
  };
}

async function runAgentsList(
  parsed: Extract<Parsed, { kind: "agents list" }>,
  client: WazuhClient
): Promise<{ code: number; text: string }> {
  const params: Record<string, string | number> = {
    limit: parsed.limit,
    offset: parsed.offset,
  };
  if (parsed.status) params.status = parsed.status;
  if (parsed.sort) params.sort = parsed.sort;

  const response = await client.getAgents(params);
  const data = response.data;
  const agents = data.affected_items.map((agent) => agentSummary(agent, parsed.includeIp));
  const result = {
    agents,
    total: data.total_affected_items,
    limit: parsed.limit,
    offset: parsed.offset,
    pagination: paginationMetadata(data.total_affected_items, parsed.limit, parsed.offset),
    output: {
      ip_included: parsed.includeIp,
    },
  };

  if (parsed.json) return { code: 0, text: jsonOut(result) };
  const lines = [`agents total=${data.total_affected_items} limit=${parsed.limit} offset=${parsed.offset}`];
  for (const agent of agents) {
    const group = Array.isArray(agent.group) ? agent.group.join(",") : "";
    lines.push(
      [
        `id=${agent.id}`,
        `name=${agent.name}`,
        `status=${agent.status}`,
        group ? `group=${group}` : undefined,
        agent.os_name ? `os=${agent.os_name}` : undefined,
        parsed.includeIp && agent.ip ? `ip=${agent.ip}` : undefined,
      ]
        .filter(Boolean)
        .join(" ")
    );
  }
  return { code: 0, text: lines.join("\n") };
}

async function runDiagnostics(
  parsed: Extract<Parsed, { kind: "diagnostics" }>,
  client: WazuhClient,
  config: WazuhConfig,
  indexerClient: WazuhIndexerClient | undefined
): Promise<{ code: number; text: string }> {
  const result = await runWazuhDiagnostics(client, config, indexerClient, parsed.checkConnectivity);
  if (parsed.json) return { code: result.status === "error" ? 1 : 0, text: jsonOut(result) };

  const lines = [
    `diagnostics status=${result.status}`,
    `manager=${result.configuration.manager_url} verify_ssl=${result.configuration.manager_verify_ssl}`,
    `indexer_configured=${result.configuration.indexer.configured}`,
  ];
  for (const check of result.checks) {
    lines.push(`${check.status}: ${check.message}`);
  }
  return { code: result.status === "error" ? 1 : 0, text: lines.join("\n") };
}

export async function run(rawArgs: string[], deps: Partial<WazuhCtrlDeps> = {}): Promise<number> {
  const resolvedDeps = { ...DEFAULT_DEPS, ...deps };
  let parsed: Parsed;
  try {
    parsed = parseArgs(rawArgs);
  } catch (error) {
    if (error instanceof UsageError) {
      resolvedDeps.err(error.message);
      resolvedDeps.err("Run wazuhctrl help for usage.");
      return 2;
    }
    throw error;
  }

  if (parsed.kind === "help") {
    resolvedDeps.out(HELP);
    return 0;
  }
  if (parsed.kind === "version") {
    resolvedDeps.out(pkg.version);
    return 0;
  }
  if (parsed.kind === "mcp") {
    await resolvedDeps.serve();
    return 0;
  }

  try {
    const config = resolvedDeps.getConfig();
    const client = resolvedDeps.makeClient(config);
    const indexerClient = config.indexer ? resolvedDeps.makeIndexerClient(config.indexer) : undefined;
    const result =
      parsed.kind === "status"
        ? await runStatus(parsed, client)
        : parsed.kind === "agents list"
          ? await runAgentsList(parsed, client)
          : await runDiagnostics(parsed, client, config, indexerClient);
    resolvedDeps.out(result.text);
    return result.code;
  } catch (error) {
    resolvedDeps.err(JSON.stringify({ error: safeCaughtErrorMessage(error, "Unexpected error") }));
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
