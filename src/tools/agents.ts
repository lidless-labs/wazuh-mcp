import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import { includeIpSchema, paginationMetadata, withOptionalField } from "./output.js";
import { agentIdSchema, limitSchema, offsetSchema, sortSchema } from "./schemas.js";

export function registerAgentTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "list_agents",
    "List all Wazuh agents with optional status filtering",
    {
      status: z
        .enum(["active", "disconnected", "never_connected", "pending"])
        .optional()
        .describe(
          "Filter by agent status: active, disconnected, never_connected, or pending"
        ),
      limit: limitSchema(10),
      offset: offsetSchema,
      sort: sortSchema(
        ["name", "-name", "+name", "id", "-id", "+id", "status", "-status", "+status"],
        "Sort field with direction prefix (e.g., '-name', '+id')"
      ),
      include_ip: includeIpSchema,
    },
    async ({ status, limit, offset, sort, include_ip = false }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (status) params.status = status;
        if (sort) params.sort = sort;

        const response = await client.getAgents(params);
        const data = response.data;

        const result = {
          agents: data.affected_items.map((agent) =>
            withOptionalField(
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
    "get_agent",
    "Get detailed information about a specific Wazuh agent by ID",
    {
      agent_id: agentIdSchema,
      include_ip: includeIpSchema,
    },
    async ({ agent_id, include_ip = false }) => {
      try {
        const response = await client.getAgent(agent_id);
        const agents = response.data.affected_items;

        if (agents.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ error: `Agent '${agent_id}' not found` }),
              },
            ],
            isError: true,
          };
        }

        const agent = agents[0];
        const result = {
          ...withOptionalField(
            withOptionalField(
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
              include_ip
            ),
            "register_ip",
            agent.registerIP,
            include_ip
          ),
          output: {
            ip_included: include_ip,
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
    "get_agent_stats",
    "Get system statistics (CPU, memory, disk) for a specific Wazuh agent",
    {
      agent_id: agentIdSchema,
    },
    async ({ agent_id }) => {
      try {
        // Verify agent exists
        const agentResponse = await client.getAgent(agent_id);
        const agents = agentResponse.data.affected_items;

        if (agents.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ error: `Agent '${agent_id}' not found` }),
              },
            ],
            isError: true,
          };
        }

        const agent = agents[0];
        const statsResponse = await client.getAgentStats(agent_id);
        const stats = statsResponse.data.affected_items[0] ?? {};

        const result = {
          agent_id: agent.id,
          agent_name: agent.name,
          cpu: stats.cpu,
          memory: stats.memory,
          disk: stats.disk,
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
}
