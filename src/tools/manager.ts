import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import { includeDescriptionSchema } from "./output.js";
import { limitSchema, managerSectionSchema, offsetSchema, optionalSearchTextSchema } from "./schemas.js";

export function registerManagerTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_manager_logs",
    "Retrieve Wazuh manager logs with optional filtering by severity level or module tag",
    {
      limit: limitSchema(25),
      offset: offsetSchema,
      level: z
        .enum(["info", "warning", "error", "critical", "debug"])
        .optional()
        .describe("Filter by log severity level"),
      tag: optionalSearchTextSchema.describe("Filter by module/tag name (e.g., 'wazuh-modulesd', 'ossec-analysisd')"),
      include_description: includeDescriptionSchema,
    },
    async ({ limit, offset, level, tag, include_description = false }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (level) params.level = level;
        if (tag) params.tag = tag;

        const response = await client.getManagerLogs(params);
        const data = response.data;

        const result = {
          logs: data.affected_items.map((entry) => ({
            timestamp: entry.timestamp,
            tag: entry.tag,
            level: entry.level,
            ...(include_description ? { description: entry.description } : {}),
          })),
          total: data.total_affected_items,
          limit,
          offset,
          output: {
            description_included: include_description,
          },
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
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

  server.tool(
    "get_manager_config",
    "Get the active Wazuh manager configuration for a specific section",
    {
      section: managerSectionSchema
        .optional()
        .describe("Configuration section to retrieve. Omit to get the full configuration."),
    },
    async ({ section }) => {
      try {
        const params: Record<string, string | number> = {};
        if (section) params.section = section;

        const response = await client.getManagerConfig(params);

        return {
          content: [{ type: "text" as const, text: JSON.stringify(response.data, null, 2) }],
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
