import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";

export function registerRootcheckTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_rootcheck",
    "Get rootkit detection scan results for a Wazuh agent",
    {
      agent_id: z
        .string()
        .describe("Agent identifier (e.g., '001')"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(25)
        .describe("Maximum number of results to return (1-100)"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("Pagination offset"),
      status: z
        .enum(["outstanding", "solved"])
        .optional()
        .describe("Filter by status: outstanding (active findings) or solved"),
    },
    async ({ agent_id, limit, offset, status }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (status) params.status = status;

        const response = await client.getRootcheck(agent_id, params);
        const data = response.data;

        const result = {
          agent_id,
          findings: data.affected_items.map((item) => ({
            status: item.status,
            event: item.event,
            day: item.day,
            old_day: item.old_day,
            cis: item.cis,
            pci_dss: item.pci_dss,
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
}
