import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { WazuhClient } from "../client.js";
import { formatToolResponse } from "./output.js";

export function registerVersionTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_wazuh_version",
    "Get the Wazuh manager version and API information",
    {},
    async () => {
      try {
        const response = await client.getVersion();
        const info = response.data;

        const result = {
          title: info.title,
          api_version: info.api_version,
          revision: info.revision,
          license: info.license_name,
          hostname: info.hostname,
          timestamp: info.timestamp,
        };

        return {
          content: [{ type: "text" as const, text: formatToolResponse(result) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
          isError: true,
        };
      }
    }
  );
}
