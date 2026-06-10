import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolErrorResponse } from "./errors.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import { formatToolResponse, includeHashesSchema, paginationMetadata } from "./output.js";
import { agentIdSchema, limitSchema, offsetSchema, optionalSearchTextSchema } from "./schemas.js";

export function registerSyscheckTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_fim_files",
    "Get File Integrity Monitoring (FIM) results for a Wazuh agent — shows monitored files, registry keys, and detected changes",
    {
      agent_id: agentIdSchema,
      limit: limitSchema(25, 500),
      offset: offsetSchema,
      search: optionalSearchTextSchema.describe("Filter by file path or name"),
      type: z
        .enum(["file", "registry_key", "registry_value"])
        .optional()
        .describe("Filter by entry type: file, registry_key, or registry_value"),
      include_hashes: includeHashesSchema,
    },
    async ({ agent_id, limit, offset, search, type, include_hashes = false }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (search) params.search = search;
        if (type) params.type = type;

        const response = await client.getFimFiles(agent_id, params);
        const data = response.data;

        const result = {
          agent_id,
          files: data.affected_items.map((entry) => ({
            file: entry.file,
            type: entry.type,
            date: entry.date,
            mtime: entry.mtime,
            size: entry.size,
            perm: entry.perm,
            uname: entry.uname,
            gname: entry.gname,
            changed_attributes: entry.changed_attributes,
            ...(include_hashes ? { md5: entry.md5, sha256: entry.sha256 } : {}),
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
          output: {
            hashes_included: include_hashes,
          },
        };

        return {
          content: [{ type: "text" as const, text: formatToolResponse(result) }],
        };
      } catch (error) {
        return toolErrorResponse(error);
      }
    }
  );
}
