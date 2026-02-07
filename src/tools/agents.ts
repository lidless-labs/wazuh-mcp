import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";

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
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(10)
        .describe("Maximum number of agents to return (1-100)"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("Pagination offset"),
      sort: z
        .string()
        .optional()
        .describe("Sort field with direction prefix (e.g., '-name', '+id')"),
    },
    async ({ status, limit, offset, sort }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (status) params.status = status;
        if (sort) params.sort = sort;

        const response = await client.getAgents(params);
        const data = response.data;

        const result = {
          agents: data.affected_items.map((agent) => ({
            id: agent.id,
            name: agent.name,
            ip: agent.ip,
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
          })),
          total: data.total_affected_items,
          limit,
          offset,
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
      agent_id: z
        .string()
        .describe("Agent identifier (e.g., '001')"),
    },
    async ({ agent_id }) => {
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
          id: agent.id,
          name: agent.name,
          ip: agent.ip,
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
          register_ip: agent.registerIP,
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
      agent_id: z
        .string()
        .describe("Agent identifier (e.g., '001')"),
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
