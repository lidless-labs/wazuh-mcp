import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
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

function configureTls(config: ReturnType<typeof getConfig>): void {
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

async function main(): Promise<void> {
  const config = getConfig();
  configureTls(config);

  const client = new WazuhClient(config);
  const indexerClient = config.indexer ? new WazuhIndexerClient(config.indexer) : undefined;

  const server = new McpServer({
    name: "wazuh-mcp",
    version: "1.0.0",
    description:
      "MCP server for the Wazuh SIEM/XDR platform - query agents, alerts, rules, and decoders",
  });

  // Register all tools
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

  // Register resources and prompts
  registerResources(server, client, indexerClient);
  registerPrompts(server);

  // Connect via stdio transport
  const transport = new StdioServerTransport();
  // Strip the draft-07 `$schema` the MCP SDK stamps on tool schemas; Anthropic
  // rejects it ("must match JSON Schema draft 2020-12") when the full tool set
  // is sent, e.g. on subagent spawns. Intercept tools/list output here.
  const __send = transport.send.bind(transport);
  (transport as any).send = (message: any) => {
    const tools = message?.result?.tools;
    if (Array.isArray(tools)) {
      for (const t of tools) {
        if (t?.inputSchema) delete t.inputSchema.$schema;
        if (t?.outputSchema) delete t.outputSchema.$schema;
      }
    }
    return __send(message);
  };
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
