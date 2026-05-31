import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { WazuhClient } from "../client.js";
import { paginationMetadata } from "./output.js";
import { limitSchema, offsetSchema, optionalSearchTextSchema, sortSchema } from "./schemas.js";

export function registerDecoderTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "list_decoders",
    "List all available Wazuh decoders with optional name filtering",
    {
      name: optionalSearchTextSchema.describe("Filter by decoder name"),
      limit: limitSchema(10),
      offset: offsetSchema,
      sort: sortSchema(["name", "-name", "+name", "filename", "-filename", "+filename"], "Sort field with direction prefix (e.g., '-name')"),
    },
    async ({ name, limit, offset, sort }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (name) params.name = name;
        if (sort) params.sort = sort;

        const response = await client.getDecoders(params);
        const data = response.data;

        const result = {
          decoders: data.affected_items.map((decoder) => ({
            name: decoder.name,
            filename: decoder.filename,
            relative_dirname: decoder.relative_dirname,
            status: decoder.status,
            position: decoder.position,
            details: decoder.details,
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
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
