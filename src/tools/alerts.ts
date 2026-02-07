import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";

export function registerAlertTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_alerts",
    "Retrieve recent security alerts from Wazuh with optional filtering",
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(10)
        .describe("Maximum number of alerts to return (1-100)"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("Pagination offset"),
      level: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Minimum rule severity level"),
      agent_id: z
        .string()
        .optional()
        .describe("Filter by agent ID"),
      rule_id: z
        .string()
        .optional()
        .describe("Filter by specific rule ID"),
      sort: z
        .string()
        .optional()
        .describe("Sort field with direction prefix (e.g., '-timestamp')"),
      search: z
        .string()
        .optional()
        .describe("Search term for full_log text"),
    },
    async ({ limit, offset, level, agent_id, rule_id, sort, search }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (level !== undefined) params.rule_level = level;
        if (agent_id) params.agent_id = agent_id;
        if (rule_id) params.rule_id = rule_id;
        if (sort) params.sort = sort;
        if (search) params.search = search;

        const response = await client.getAlerts(params);
        const data = response.data;

        const result = {
          alerts: data.affected_items.map((alert) => ({
            id: alert.id,
            timestamp: alert.timestamp,
            rule_id: alert.rule?.id,
            rule_level: alert.rule?.level,
            rule_description: alert.rule?.description,
            rule_groups: alert.rule?.groups,
            agent_id: alert.agent?.id,
            agent_name: alert.agent?.name,
            location: alert.location,
            decoder: alert.decoder?.name,
            full_log: alert.full_log,
            mitre: alert.rule?.mitre,
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
    "get_alert",
    "Retrieve a single security alert by its ID",
    {
      alert_id: z
        .string()
        .describe("Alert identifier"),
    },
    async ({ alert_id }) => {
      try {
        const response = await client.getAlerts({ search: alert_id, limit: 1 });
        const data = response.data;

        if (data.affected_items.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ error: `Alert '${alert_id}' not found` }),
              },
            ],
            isError: true,
          };
        }

        const alert = data.affected_items[0];
        const result = {
          id: alert.id,
          timestamp: alert.timestamp,
          rule_id: alert.rule?.id,
          rule_level: alert.rule?.level,
          rule_description: alert.rule?.description,
          rule_groups: alert.rule?.groups,
          agent_id: alert.agent?.id,
          agent_name: alert.agent?.name,
          location: alert.location,
          decoder: alert.decoder?.name,
          full_log: alert.full_log,
          mitre: alert.rule?.mitre,
          data: alert.data,
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
    "search_alerts",
    "Perform full-text search across Wazuh security alerts",
    {
      query: z
        .string()
        .describe("Search query string"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(10)
        .describe("Maximum number of alerts to return (1-100)"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("Pagination offset"),
      level: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Minimum rule severity level"),
      agent_id: z
        .string()
        .optional()
        .describe("Filter by agent ID"),
    },
    async ({ query, limit, offset, level, agent_id }) => {
      try {
        const params: Record<string, string | number> = {
          search: query,
          limit,
          offset,
        };
        if (level !== undefined) params.rule_level = level;
        if (agent_id) params.agent_id = agent_id;

        const response = await client.getAlerts(params);
        const data = response.data;

        const result = {
          alerts: data.affected_items.map((alert) => ({
            id: alert.id,
            timestamp: alert.timestamp,
            rule_id: alert.rule?.id,
            rule_level: alert.rule?.level,
            rule_description: alert.rule?.description,
            rule_groups: alert.rule?.groups,
            agent_id: alert.agent?.id,
            agent_name: alert.agent?.name,
            location: alert.location,
            decoder: alert.decoder?.name,
            full_log: alert.full_log,
            mitre: alert.rule?.mitre,
          })),
          total: data.total_affected_items,
          query,
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
}
