import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import type { WazuhIndexerClient } from "../indexer-client.js";
import {
  includeFullLogSchema,
  includeRawDataSchema,
  paginationMetadata,
  withOptionalField,
} from "./output.js";
import {
  agentIdSchema,
  alertIdSchema,
  dateTimeSchema,
  limitSchema,
  offsetSchema,
  optionalSearchTextSchema,
  ruleIdFilterSchema,
  searchTextSchema,
} from "./schemas.js";

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
      limit: limitSchema(10),
      offset: offsetSchema,
      level: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Minimum rule severity level"),
      agent_id: agentIdSchema.optional().describe("Filter by agent ID"),
      rule_id: ruleIdFilterSchema.optional(),
      sort: alertSortSchema,
      search: optionalSearchTextSchema.describe("Search term for full_log text"),
      start_time: dateTimeSchema.optional().describe("Only return alerts at or after this timestamp"),
      end_time: dateTimeSchema.optional().describe("Only return alerts at or before this timestamp"),
      include_full_log: includeFullLogSchema,
    },
    async ({
      limit,
      offset,
      level,
      agent_id,
      rule_id,
      sort = "-timestamp",
      search,
      start_time,
      end_time,
      include_full_log = false,
    }) => {
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
          start_time,
          end_time,
          sortOrder: parseTimestampSort(sort),
        });

        const result = {
          alerts: alerts.map((alert) =>
            withOptionalField(
              {
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
                mitre: alert.rule?.mitre,
              },
              "full_log",
              alert.full_log,
              include_full_log
            )
          ),
          total,
          limit,
          offset,
          pagination: paginationMetadata(total, limit, offset),
          sort,
          start_time,
          end_time,
          output: {
            full_log_included: include_full_log,
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
    "get_alert",
    "Retrieve a single security alert by its ID",
    {
      alert_id: alertIdSchema,
      include_full_log: includeFullLogSchema,
      include_raw_data: includeRawDataSchema,
    },
    async ({ alert_id, include_full_log = false, include_raw_data = false }) => {
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

        const summary = withOptionalField(
          withOptionalField(
            {
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
              mitre: alert.rule?.mitre,
            },
            "full_log",
            alert.full_log,
            include_full_log
          ),
          "data",
          alert.data,
          include_raw_data
        );
        const result = {
          ...summary,
          output: {
            full_log_included: include_full_log,
            raw_data_included: include_raw_data,
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
    "search_alerts",
    "Perform full-text search across Wazuh security alerts",
    {
      query: searchTextSchema.describe("Search query string"),
      limit: limitSchema(10),
      offset: offsetSchema,
      level: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Minimum rule severity level"),
      agent_id: agentIdSchema.optional().describe("Filter by agent ID"),
      start_time: dateTimeSchema.optional().describe("Only return alerts at or after this timestamp"),
      end_time: dateTimeSchema.optional().describe("Only return alerts at or before this timestamp"),
      include_full_log: includeFullLogSchema,
    },
    async ({
      query,
      limit,
      offset,
      level,
      agent_id,
      start_time,
      end_time,
      include_full_log = false,
    }) => {
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
          start_time,
          end_time,
        });

        const result = {
          alerts: alerts.map((alert) =>
            withOptionalField(
              {
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
                mitre: alert.rule?.mitre,
              },
              "full_log",
              alert.full_log,
              include_full_log
            )
          ),
          total,
          query,
          limit,
          offset,
          pagination: paginationMetadata(total, limit, offset),
          start_time,
          end_time,
          output: {
            full_log_included: include_full_log,
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
}
