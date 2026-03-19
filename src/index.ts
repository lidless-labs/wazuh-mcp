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
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

async function main(): Promise<void> {
  const config = getConfig();

  // Disable TLS verification if configured
  if (!config.verifySsl) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

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

  // Register resources and prompts
  registerResources(server, client, indexerClient);
  registerPrompts(server);

  // Connect via stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
