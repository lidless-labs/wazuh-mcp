import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";

export function registerScaTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "get_sca_policies",
    "List Security Configuration Assessment (SCA) policies evaluated on a Wazuh agent",
    {
      agent_id: z
        .string()
        .describe("Agent identifier (e.g., '001')"),
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
      agent_id: z
        .string()
        .describe("Agent identifier (e.g., '001')"),
      policy_id: z
        .string()
        .describe("SCA policy identifier (e.g., 'cis_debian10')"),
      result: z
        .enum(["passed", "failed", "not applicable"])
        .optional()
        .describe("Filter by check result: passed, failed, or not applicable"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(500)
        .default(25)
        .describe("Maximum number of checks to return (1-500)"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("Pagination offset"),
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
