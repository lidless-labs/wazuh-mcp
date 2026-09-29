import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig, type WazuhConfig } from "./config.js";
import { WazuhClient } from "./client.js";
import { WazuhIndexerClient } from "./indexer-client.js";
import { registerAgentTools } from "./tools/agents.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerRuleTools } from "./tools/rules.js";
import { registerDecoderTools } from "./tools/decoders.js";
import { registerVersionTools } from "./tools/version.js";
import { registerScaTools } from "./tools/sca.js";
import { registerSyscollectorTools } from "./tools/syscollector.js";
import { registerRootcheckTools } from "./tools/rootcheck.js";
import { registerSyscheckTools } from "./tools/syscheck.js";
import { registerManagerTools } from "./tools/manager.js";
import { registerGroupTools } from "./tools/groups.js";
import { registerDiagnosticTools } from "./tools/diagnostics.js";
import { registerVulnerabilityTools } from "./tools/vulnerabilities.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
) as { version: string };

export function configureTls(config: WazuhConfig): void {
  const insecureTargets: string[] = [];
  if (!config.verifySsl) insecureTargets.push("Wazuh manager");
  if (config.indexer && !config.indexer.verifySsl) insecureTargets.push("Wazuh Indexer");

  if (insecureTargets.length > 0) {
    console.error(
      `Warning: TLS certificate verification is disabled for ${insecureTargets.join(
        " and "
      )}. Verification is disabled only for those configured clients. Use this only for trusted self-signed lab environments.`
    );
  }
}

export interface WazuhServerDeps {
  config?: WazuhConfig;
  client?: WazuhClient;
  indexerClient?: WazuhIndexerClient;
}

export function createWazuhMcpServer(deps: WazuhServerDeps = {}): McpServer {
  const config = deps.config ?? getConfig();
  const client = deps.client ?? new WazuhClient(config);
  const indexerClient =
    deps.indexerClient ?? (config.indexer ? new WazuhIndexerClient(config.indexer) : undefined);

  const server = new McpServer({
    name: "wazuh-mcp",
    version: pkg.version,
    description:
      "MCP server for the Wazuh SIEM/XDR platform - query agents, alerts, rules, and decoders",
  });

  registerAgentTools(server, client);
  registerAlertTools(server, client, indexerClient);
  registerRuleTools(server, client);
  registerDecoderTools(server, client);
  registerVersionTools(server, client);
  registerScaTools(server, client);
  registerSyscollectorTools(server, client);
  registerRootcheckTools(server, client);
  registerSyscheckTools(server, client);
  registerManagerTools(server, client);
  registerGroupTools(server, client);
  registerDiagnosticTools(server, client, config, indexerClient);
  registerVulnerabilityTools(server, indexerClient);

  registerResources(server, client, indexerClient);
  registerPrompts(server);

  return server;
}

function stripSchemaFromToolList(transport: StdioServerTransport): void {
  const send = transport.send.bind(transport);
  (transport as unknown as { send: typeof transport.send }).send = (message) => {
    const tools = (message as { result?: { tools?: unknown } })?.result?.tools;
    if (Array.isArray(tools)) {
      for (const tool of tools) {
        if (tool?.inputSchema) delete tool.inputSchema.$schema;
        if (tool?.outputSchema) delete tool.outputSchema.$schema;
      }
    }
    return send(message);
  };
}

export async function serveMcp(): Promise<void> {
  const config = getConfig();
  configureTls(config);
  const server = createWazuhMcpServer({ config });
  const transport = new StdioServerTransport();
  stripSchemaFromToolList(transport);
  await server.connect(transport);
}
