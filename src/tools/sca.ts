import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import { paginationMetadata } from "./output.js";
import { agentIdSchema, limitSchema, offsetSchema, policyIdSchema } from "./schemas.js";

export function registerScaTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_sca_policies",
    "List Security Configuration Assessment (SCA) policies evaluated on a Wazuh agent",
    {
      agent_id: agentIdSchema,
    },
    async ({ agent_id }) => {
      try {
        const response = await client.getScaPolicies(agent_id);
        const data = response.data;

        const result = {
          agent_id,
          policies: data.affected_items.map((policy) => ({
            policy_id: policy.policy_id,
            name: policy.name,
            description: policy.description,
            score: policy.score,
            pass: policy.pass,
            fail: policy.fail,
            invalid: policy.invalid,
            total_checks: policy.total_checks,
            hash_file: policy.hash_file,
            end_scan: policy.end_scan,
          })),
          total: data.total_affected_items,
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
    "get_sca_checks",
    "Get individual check results for a specific SCA policy on a Wazuh agent",
    {
      agent_id: agentIdSchema,
      policy_id: policyIdSchema,
      result: z
        .enum(["passed", "failed", "not applicable"])
        .optional()
        .describe("Filter by check result: passed, failed, or not applicable"),
      limit: limitSchema(25, 500),
      offset: offsetSchema,
    },
    async ({ agent_id, policy_id, result, limit, offset }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (result) params.result = result;

        const response = await client.getScaChecks(agent_id, policy_id, params);
        const data = response.data;

        const mapped = {
          agent_id,
          policy_id,
          checks: data.affected_items.map((check) => ({
            id: check.id,
            title: check.title,
            description: check.description,
            rationale: check.rationale,
            remediation: check.remediation,
            result: check.result,
            condition: check.condition,
            command: check.command,
            references: check.references,
            compliance: check.compliance,
            reason: check.reason,
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(mapped, null, 2) }],
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
