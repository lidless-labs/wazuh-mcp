import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { WazuhIndexerClient } from "../indexer-client.js";
import { includeDescriptionSchema, paginationMetadata } from "./output.js";
import {
  agentIdSchema,
  cveIdSchema,
  limitSchema,
  offsetSchema,
  optionalSearchTextSchema,
  severitySchema,
} from "./schemas.js";

const NO_INDEXER_MSG =
  "Vulnerability inventory requires WAZUH_INDEXER_URL configuration. Current Wazuh versions store vulnerability inventory in the Wazuh Indexer.";

function formatVulnerability(
  item: Awaited<ReturnType<WazuhIndexerClient["searchVulnerabilities"]>>["vulnerabilities"][number],
  includeDescription: boolean
): Record<string, unknown> {
  return {
    id: item.id,
    cve_id: item.vulnerability?.id,
    severity: item.vulnerability?.severity,
    score: item.vulnerability?.score?.base,
    detected_at: item.vulnerability?.detected_at,
    published_at: item.vulnerability?.published_at,
    category: item.vulnerability?.category,
    package_name: item.package?.name,
    package_version: item.package?.version,
    package_type: item.package?.type,
    agent_id: item.agent?.id,
    agent_name: item.agent?.name,
    os_name: item.host?.os?.name,
    os_version: item.host?.os?.version,
    ...(includeDescription ? { description: item.vulnerability?.description } : {}),
  };
}

export function registerVulnerabilityTools(
  server: McpServer,
  indexerClient?: WazuhIndexerClient
): void {
  server.tool(
    "list_vulnerabilities",
    "List Wazuh vulnerability inventory from the Wazuh Indexer",
    {
      limit: limitSchema(10),
      offset: offsetSchema,
      cve_id: cveIdSchema.optional(),
      agent_id: agentIdSchema.optional().describe("Filter by agent ID"),
      severity: severitySchema.optional().describe("Filter by vulnerability severity"),
      package_name: optionalSearchTextSchema.describe("Filter by affected package name"),
      include_description: includeDescriptionSchema,
    },
    async ({
      limit,
      offset,
      cve_id,
      agent_id,
      severity,
      package_name,
      include_description = false,
    }) => {
      if (!indexerClient) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: NO_INDEXER_MSG }) }],
          isError: true,
        };
      }

      try {
        const { vulnerabilities, total } = await indexerClient.searchVulnerabilities(limit, offset, {
          cve_id,
          agent_id,
          severity,
          package_name,
        });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  vulnerabilities: vulnerabilities.map((item) =>
                    formatVulnerability(item, include_description)
                  ),
                  total,
                  limit,
                  offset,
                  pagination: paginationMetadata(total, limit, offset),
                  output: {
                    description_included: include_description,
                  },
                },
                null,
                2
              ),
            },
          ],
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
    "search_vulnerabilities",
    "Search Wazuh vulnerability inventory by CVE, package, agent, or description",
    {
      query: optionalSearchTextSchema.describe("Search query for CVE, package, agent, or description"),
      limit: limitSchema(10),
      offset: offsetSchema,
      severity: severitySchema.optional().describe("Filter by vulnerability severity"),
      agent_id: agentIdSchema.optional().describe("Filter by agent ID"),
      include_description: includeDescriptionSchema,
    },
    async ({ query, limit, offset, severity, agent_id, include_description = false }) => {
      if (!indexerClient) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: NO_INDEXER_MSG }) }],
          isError: true,
        };
      }

      try {
        const { vulnerabilities, total } = await indexerClient.searchVulnerabilities(limit, offset, {
          search: query,
          severity,
          agent_id,
        });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  vulnerabilities: vulnerabilities.map((item) =>
                    formatVulnerability(item, include_description)
                  ),
                  total,
                  query,
                  limit,
                  offset,
                  pagination: paginationMetadata(total, limit, offset),
                  output: {
                    description_included: include_description,
                  },
                },
                null,
                2
              ),
            },
          ],
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
