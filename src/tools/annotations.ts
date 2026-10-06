import type { McpServer, RegisteredTool, ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShapeCompat } from "@modelcontextprotocol/sdk/server/zod-compat.js";
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

/**
 * MCP tool annotations shared by every wazuh-mcp tool.
 *
 * - `readOnlyHint: true`: no tool modifies Wazuh state. The only POSTs are JWT
 *   authentication and indexer `_search`.
 * - `openWorldHint: true`: the tools query only the operator's own Wazuh
 *   manager and indexer, but most of what they return (alerts, logs, agent
 *   names, inventory) originates on monitored endpoints and can be written by
 *   an attacker. The hint tells clients to treat tool output as untrusted, in
 *   line with the `<untrusted_siem_data>` markers.
 *
 * `destructiveHint` and `idempotentHint` are omitted on purpose: the MCP
 * specification defines them as meaningful only when `readOnlyHint` is false.
 */
export const READ_ONLY_TOOL_ANNOTATIONS: Readonly<ToolAnnotations> = Object.freeze({
  readOnlyHint: true,
  openWorldHint: true,
});

/**
 * Register a wazuh-mcp tool with the shared read-only annotations through the
 * SDK's `registerTool` API. The name, description, and input schema are passed
 * through unchanged.
 */
export function registerReadOnlyTool<Args extends ZodRawShapeCompat>(
  server: McpServer,
  name: string,
  description: string,
  inputSchema: Args,
  callback: ToolCallback<Args>
): RegisteredTool {
  return server.registerTool(
    name,
    { description, inputSchema, annotations: READ_ONLY_TOOL_ANNOTATIONS },
    callback
  );
}
