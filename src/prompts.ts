import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerPrompts(server: McpServer): void {
  server.prompt(
    "investigate-alert",
    "Investigate a Wazuh security alert and provide analysis with remediation steps",
    { alert_id: z.string().describe("The alert ID to investigate") },
    ({ alert_id }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Investigate Wazuh alert ${alert_id}. Please:`,
              "",
              "1. Use get_alert to retrieve the full alert details",
              "2. Use get_rule to look up the triggered rule",
              "3. Use get_agent to check the affected agent's status",
              "4. Analyze the alert context (MITRE ATT&CK mapping, compliance frameworks)",
              "5. Determine severity and potential impact",
              "6. Suggest specific remediation steps",
              "7. Recommend additional monitoring or detection rules if needed",
            ].join("\n"),
          },
        },
      ],
    })
  );

  server.prompt(
    "agent-health-check",
    "Perform a comprehensive health check on a Wazuh agent",
    { agent_id: z.string().describe("The agent ID to check") },
    ({ agent_id }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Perform a health check on Wazuh agent ${agent_id}. Please:`,
              "",
              "1. Use get_agent to retrieve agent details and connection status",
              "2. Use get_agent_stats to check CPU, memory, and disk usage",
              "3. Use get_alerts with agent_id filter to find recent alerts for this agent",
              "4. Identify any resource concerns (high CPU, low disk, memory pressure)",
              "5. Flag any critical or high-severity alerts",
              "6. Provide an overall health assessment and recommendations",
            ].join("\n"),
          },
        },
      ],
    })
  );

  server.prompt(
    "security-overview",
    "Generate a security overview of the Wazuh environment",
    {},
    () => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              "Generate a security overview of the Wazuh environment. Please:",
              "",
              "1. Use get_wazuh_version to confirm the Wazuh version",
              "2. Use list_agents to see all agents and their status",
              "3. Use get_alerts with sort=-timestamp to find the most recent alerts",
              "4. Use get_alerts with level >= 12 to find critical alerts",
              "5. Summarize:",
              "   - Total agents (active vs disconnected)",
              "   - Alert volume and severity distribution",
              "   - Top triggered rules",
              "   - Any MITRE ATT&CK techniques detected",
              "   - Compliance coverage (PCI-DSS, HIPAA, GDPR)",
              "6. Highlight any immediate concerns requiring attention",
            ].join("\n"),
          },
        },
      ],
    })
  );
}
