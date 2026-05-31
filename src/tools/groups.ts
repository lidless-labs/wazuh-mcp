import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { WazuhClient } from "../client.js";
import { formatToolResponse, includeIpSchema, paginationMetadata, withOptionalField } from "./output.js";
import { groupIdSchema, limitSchema, offsetSchema } from "./schemas.js";

export function registerGroupTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "list_groups",
    "List all Wazuh agent groups",
    {
      limit: limitSchema(25),
      offset: offsetSchema,
    },
    async ({ limit, offset }) => {
      try {
        const response = await client.getGroups({ limit, offset });
        const data = response.data;

        const result = {
          groups: data.affected_items.map((group) => ({
            name: group.name,
            count: group.count,
            config_sum: group.configSum,
            merged_sum: group.mergedSum,
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
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

  server.tool(
    "get_group_agents",
    "List agents belonging to a specific Wazuh group",
    {
      group_id: groupIdSchema,
      limit: limitSchema(25),
      offset: offsetSchema,
      include_ip: includeIpSchema,
    },
    async ({ group_id, limit, offset, include_ip = false }) => {
      try {
        const response = await client.getGroupAgents(group_id, { limit, offset });
        const data = response.data;

        const result = {
          group_id,
          agents: data.affected_items.map((agent) =>
            withOptionalField(
              {
                id: agent.id,
                name: agent.name,
                status: agent.status,
                os_name: agent.os?.name,
                os_platform: agent.os?.platform,
                version: agent.version,
                last_keepalive: agent.lastKeepAlive,
              },
              "ip",
              agent.ip,
              include_ip
            )
          ),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
          output: {
            ip_included: include_ip,
          },
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
