import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import type { WazuhConfig } from "../config.js";
import type { WazuhIndexerClient } from "../indexer-client.js";

type DiagnosticStatus = "ok" | "warning" | "error";

interface CheckResult {
  status: DiagnosticStatus;
  message: string;
  details?: Record<string, unknown>;
}

function sanitizeUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    if (url.username) url.username = "redacted";
    if (url.password) url.password = "redacted";
    return url.toString();
  } catch {
    return rawUrl.replace(/\/\/([^:@/]+):([^@/]+)@/, "//redacted:redacted@");
  }
}

function combineStatus(checks: CheckResult[]): DiagnosticStatus {
  if (checks.some((check) => check.status === "error")) return "error";
  if (checks.some((check) => check.status === "warning")) return "warning";
  return "ok";
}

export function registerDiagnosticTools(
  server: McpServer,
  client: WazuhClient,
  config: WazuhConfig,
  indexerClient?: WazuhIndexerClient
): void {
  server.tool(
    "diagnose_wazuh_connection",
    "Check Wazuh MCP configuration and connectivity without exposing credentials",
    {
      check_connectivity: z
        .boolean()
        .default(true)
        .describe("When true, make lightweight requests to the manager and configured indexer"),
    },
    async ({ check_connectivity = true }) => {
      const checks: CheckResult[] = [];

      if (!config.verifySsl) {
        checks.push({
          status: "warning",
          message: "WAZUH_VERIFY_SSL is false. TLS certificate verification is disabled process-wide.",
        });
      }
      if (config.indexer && !config.indexer.verifySsl) {
        checks.push({
          status: "warning",
          message:
            "WAZUH_INDEXER_VERIFY_SSL is false. TLS certificate verification is disabled process-wide.",
        });
      }
      if (!config.indexer) {
        checks.push({
          status: "warning",
          message: "WAZUH_INDEXER_URL is not configured, alert tools and alert resources are unavailable.",
        });
      }

      if (check_connectivity) {
        try {
          const response = await client.getVersion();
          checks.push({
            status: "ok",
            message: "Wazuh manager API is reachable.",
            details: {
              api_version: response.data.api_version,
              hostname: response.data.hostname,
              revision: response.data.revision,
            },
          });
        } catch (error) {
          checks.push({
            status: "error",
            message: `Wazuh manager API check failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
          });
        }

        if (indexerClient) {
          try {
            const info = await indexerClient.getInfo();
            checks.push({
              status: "ok",
              message: "Wazuh Indexer is reachable.",
              details: {
                cluster_name: info.cluster_name,
                version:
                  typeof info.version === "object" && info.version !== null
                    ? (info.version as Record<string, unknown>).number
                    : undefined,
              },
            });
          } catch (error) {
            checks.push({
              status: "error",
              message: `Wazuh Indexer check failed: ${
                error instanceof Error ? error.message : String(error)
              }`,
            });
          }
        }
      }

      const result = {
        status: combineStatus(checks),
        configuration: {
          manager_url: sanitizeUrl(config.url),
          manager_verify_ssl: config.verifySsl,
          timeout_ms: config.timeout,
          indexer: config.indexer
            ? {
                configured: true,
                url: sanitizeUrl(config.indexer.url),
                verify_ssl: config.indexer.verifySsl,
              }
            : {
                configured: false,
              },
        },
        checks,
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        isError: result.status === "error",
      };
    }
  );
}
