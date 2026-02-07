import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { WazuhClient } from "./client.js";

export function registerResources(
  server: McpServer,
  client: WazuhClient
): void {
  server.resource(
    "wazuh-agents",
    "wazuh://agents",
    {
      description: "List of all registered Wazuh agents and their current status",
      mimeType: "application/json",
    },
    async () => {
      const response = await client.getAgents({ limit: 100 });
      const agents = response.data.affected_items.map((agent) => ({
        id: agent.id,
        name: agent.name,
        ip: agent.ip,
        status: agent.status,
        group: agent.group,
        os: agent.os?.name,
        version: agent.version,
        last_keepalive: agent.lastKeepAlive,
      }));

      return {
        contents: [
          {
            uri: "wazuh://agents",
            mimeType: "application/json",
            text: JSON.stringify(
              { agents, total: response.data.total_affected_items },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.resource(
    "wazuh-alerts-recent",
    "wazuh://alerts/recent",
    {
      description: "Recent security alerts from Wazuh (last 25)",
      mimeType: "application/json",
    },
    async () => {
      const response = await client.getAlerts({
        limit: 25,
        sort: "-timestamp",
      });
      const alerts = response.data.affected_items.map((alert) => ({
        id: alert.id,
        timestamp: alert.timestamp,
        rule_id: alert.rule?.id,
        rule_level: alert.rule?.level,
        rule_description: alert.rule?.description,
        agent_id: alert.agent?.id,
        agent_name: alert.agent?.name,
      }));

      return {
        contents: [
          {
            uri: "wazuh://alerts/recent",
            mimeType: "application/json",
            text: JSON.stringify(
              { alerts, total: response.data.total_affected_items },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.resource(
    "wazuh-rules-summary",
    "wazuh://rules/summary",
    {
      description: "Summary of Wazuh detection rules by severity level",
      mimeType: "application/json",
    },
    async () => {
      const response = await client.getRules({ limit: 100, sort: "-level" });
      const rules = response.data.affected_items.map((rule) => ({
        id: rule.id,
        description: rule.description,
        level: rule.level,
        groups: rule.groups,
      }));

      return {
        contents: [
          {
            uri: "wazuh://rules/summary",
            mimeType: "application/json",
            text: JSON.stringify(
              { rules, total: response.data.total_affected_items },
              null,
              2
            ),
          },
        ],
      };
    }
  );
}
