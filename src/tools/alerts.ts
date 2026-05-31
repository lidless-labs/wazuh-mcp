import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import type { WazuhIndexerClient } from "../indexer-client.js";

const NO_INDEXER_MSG =
  "Alerts require WAZUH_INDEXER_URL configuration. Wazuh 4.x stores alerts in the Wazuh Indexer (OpenSearch), not the REST API.";
const alertSortSchema = z
  .enum(["timestamp", "-timestamp", "+timestamp"])
  .default("-timestamp")
  .describe("Sort by timestamp. Use '-timestamp' for newest first or '+timestamp' for oldest first.");

function parseTimestampSort(sort: z.infer<typeof alertSortSchema>): "asc" | "desc" {
  return sort.startsWith("+") ? "asc" : "desc";
}

export function registerAlertTools(
  server: McpServer,
  _client: WazuhClient,
  indexerClient?: WazuhIndexerClient
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
      sort: alertSortSchema,
      search: z
        .string()
        .optional()
        .describe("Search term for full_log text"),
    },
    async ({ limit, offset, level, agent_id, rule_id, sort = "-timestamp", search }) => {
      if (!indexerClient) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: NO_INDEXER_MSG }) }],
          isError: true,
        };
      }

      try {
        const { alerts, total } = await indexerClient.getRecentAlerts(limit, offset, {
          level,
          agent_id,
          rule_id,
          search,
          sortOrder: parseTimestampSort(sort),
        });

        const result = {
          alerts: alerts.map((alert) => ({
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
          total,
          limit,
          offset,
          sort,
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
      if (!indexerClient) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: NO_INDEXER_MSG }) }],
          isError: true,
        };
      }

      try {
        const alert = await indexerClient.getAlert(alert_id);

        if (!alert) {
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
      if (!indexerClient) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: NO_INDEXER_MSG }) }],
          isError: true,
        };
      }

      try {
        const { alerts, total } = await indexerClient.fullTextSearch(query, limit, offset, {
          level,
          agent_id,
        });

        const result = {
          alerts: alerts.map((alert) => ({
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
          total,
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
