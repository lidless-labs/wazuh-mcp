import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import { formatToolResponse, paginationMetadata } from "./output.js";
import {
  limitSchema,
  offsetSchema,
  optionalSearchTextSchema,
  ruleIdSchema,
  searchTextSchema,
  sortSchema,
} from "./schemas.js";

export function registerRuleTools(
  server: McpServer,
  client: WazuhClient
): void {
  server.tool(
    "list_rules",
    "List all Wazuh rules with optional level and group filtering",
    {
      level: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Filter by rule severity level"),
      group: optionalSearchTextSchema.describe("Filter by rule group name"),
      limit: limitSchema(10),
      offset: offsetSchema,
      sort: sortSchema(["level", "-level", "+level", "id", "-id", "+id"], "Sort field with direction prefix (e.g., '-level')"),
    },
    async ({ level, group, limit, offset, sort }) => {
      try {
        const params: Record<string, string | number> = { limit, offset };
        if (level !== undefined) params.level = level;
        if (group) params.group = group;
        if (sort) params.sort = sort;

        const response = await client.getRules(params);
        const data = response.data;

        const result = {
          rules: data.affected_items.map((rule) => ({
            id: rule.id,
            description: rule.description,
            level: rule.level,
            groups: rule.groups,
            pci_dss: rule.pci_dss,
            gdpr: rule.gdpr,
            gpg13: rule.gpg13,
            hipaa: rule.hipaa,
            nist_800_53: rule.nist_800_53,
            tsc: rule.tsc,
            mitre: rule.mitre,
            details: rule.details,
          })),
          total: data.total_affected_items,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
        };

        return {
          content: [{ type: "text" as const, text: formatToolResponse(result) }],
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
    "get_rule",
    "Get detailed information about a specific Wazuh rule by ID",
    {
      rule_id: ruleIdSchema,
    },
    async ({ rule_id }) => {
      try {
        const response = await client.getRule(rule_id);
        const rules = response.data.affected_items;

        if (rules.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ error: `Rule '${rule_id}' not found` }),
              },
            ],
            isError: true,
          };
        }

        const rule = rules[0];
        const result = {
          id: rule.id,
          description: rule.description,
          level: rule.level,
          groups: rule.groups,
          filename: rule.filename,
          relative_dirname: rule.relative_dirname,
          status: rule.status,
          pci_dss: rule.pci_dss,
          gdpr: rule.gdpr,
          gpg13: rule.gpg13,
          hipaa: rule.hipaa,
          nist_800_53: rule.nist_800_53,
          tsc: rule.tsc,
          mitre: rule.mitre,
          details: rule.details,
        };

        return {
          content: [{ type: "text" as const, text: formatToolResponse(result) }],
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
    "search_rules",
    "Search Wazuh rules by description text",
    {
      description: searchTextSchema.describe("Search term to match against rule descriptions"),
      limit: limitSchema(10),
      offset: offsetSchema,
      level: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Minimum severity level filter"),
    },
    async ({ description, limit, offset, level }) => {
      try {
        const params: Record<string, string | number> = {
          search: description,
          limit,
          offset,
        };
        if (level !== undefined) params.level = level;

        const response = await client.getRules(params);
        const data = response.data;

        const result = {
          rules: data.affected_items.map((rule) => ({
            id: rule.id,
            description: rule.description,
            level: rule.level,
            groups: rule.groups,
            pci_dss: rule.pci_dss,
            gdpr: rule.gdpr,
            gpg13: rule.gpg13,
            hipaa: rule.hipaa,
            nist_800_53: rule.nist_800_53,
            tsc: rule.tsc,
            mitre: rule.mitre,
            details: rule.details,
          })),
          total: data.total_affected_items,
          description,
          limit,
          offset,
          pagination: paginationMetadata(data.total_affected_items, limit, offset),
        };

        return {
          content: [{ type: "text" as const, text: formatToolResponse(result) }],
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
