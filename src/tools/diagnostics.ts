import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { WazuhClient } from "../client.js";
import type { WazuhConfig } from "../config.js";
import type { WazuhIndexerClient } from "../indexer-client.js";
import { safeCaughtErrorMessage } from "../safe-error.js";
import { formatToolResponse } from "./output.js";

type DiagnosticStatus = "ok" | "warning" | "error";

export interface CheckResult {
  status: DiagnosticStatus;
  message: string;
  details?: Record<string, unknown>;
}

export interface WazuhDiagnosticResult {
  status: DiagnosticStatus;
  configuration: {
    manager_url: string;
    manager_verify_ssl: boolean;
    timeout_ms: number;
    node_tls_reject_unauthorized: string | null;
    indexer:
      | {
          configured: true;
          url: string;
          verify_ssl: boolean;
          timeout_ms: number;
        }
      | {
          configured: false;
        };
  };
  checks: CheckResult[];
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

function urlCheck(name: string, rawUrl: string): CheckResult {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") {
      return {
        status: "warning",
        message: `${name} URL does not use HTTPS.`,
        details: {
          protocol: url.protocol.replace(":", ""),
        },
      };
    }
    return {
      status: "ok",
      message: `${name} URL uses HTTPS.`,
      details: {
        protocol: "https",
      },
    };
  } catch {
    return {
      status: "error",
      message: `${name} URL is invalid.`,
    };
  }
}

export async function runWazuhDiagnostics(
  client: WazuhClient,
  config: WazuhConfig,
  indexerClient: WazuhIndexerClient | undefined,
  checkConnectivity = true
): Promise<WazuhDiagnosticResult> {
  const checks: CheckResult[] = [];

  checks.push(urlCheck("Wazuh manager", config.url));
  if (config.indexer) {
    checks.push(urlCheck("Wazuh Indexer", config.indexer.url));
  }

  if (!config.verifySsl) {
    checks.push({
      status: "warning",
      message: "WAZUH_VERIFY_SSL is false. TLS certificate verification is disabled for Wazuh manager requests.",
    });
  }
  if (config.indexer && !config.indexer.verifySsl) {
    checks.push({
      status: "warning",
      message:
        "WAZUH_INDEXER_VERIFY_SSL is false. TLS certificate verification is disabled for Wazuh Indexer requests.",
    });
  }
  if (!config.indexer) {
    checks.push({
      status: "warning",
      message:
        "WAZUH_INDEXER_URL is not configured, alert and vulnerability tools plus alert resources are unavailable.",
    });
  }

  checks.push({
    status: process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" ? "warning" : "ok",
    message:
      process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"
        ? "Node TLS verification is disabled for this process."
        : "Node TLS verification is enabled for this process.",
  });

  if (checkConnectivity) {
    let managerAuthenticated = false;
    try {
      await client.authenticate();
      managerAuthenticated = true;
      checks.push({
        status: "ok",
        message: "Wazuh manager authentication succeeded.",
      });
    } catch (error) {
      checks.push({
        status: "error",
        message: `Wazuh manager authentication failed: ${safeCaughtErrorMessage(error, "unknown error")}`,
      });
    }

    if (managerAuthenticated) {
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
          message: `Wazuh manager version check failed: ${safeCaughtErrorMessage(error, "unknown error")}`,
        });
      }
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
          message: `Wazuh Indexer check failed: ${safeCaughtErrorMessage(error, "unknown error")}`,
        });
      }

      for (const [label, indexPattern] of [
        ["alert index", "wazuh-alerts-*"],
        ["vulnerability index", "wazuh-states-vulnerabilities*"],
      ] as const) {
        try {
          const exists = await indexerClient.indexExists(indexPattern);
          checks.push({
            status: exists ? "ok" : "warning",
            message: exists
              ? `Wazuh Indexer ${label} is available.`
              : `Wazuh Indexer ${label} was not found.`,
            details: {
              index_pattern: indexPattern,
            },
          });
        } catch (error) {
          checks.push({
            status: "error",
            message: `Wazuh Indexer ${label} readiness check failed: ${safeCaughtErrorMessage(error, "unknown error")}`,
            details: {
              index_pattern: indexPattern,
            },
          });
        }
      }
    }
  }

  return {
    status: combineStatus(checks),
    configuration: {
      manager_url: sanitizeUrl(config.url),
      manager_verify_ssl: config.verifySsl,
      timeout_ms: config.timeout,
      node_tls_reject_unauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED ?? null,
      indexer: config.indexer
        ? {
            configured: true,
            url: sanitizeUrl(config.indexer.url),
            verify_ssl: config.indexer.verifySsl,
            timeout_ms: config.indexer.timeout,
          }
        : {
            configured: false,
          },
    },
    checks,
  };
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
      const result = await runWazuhDiagnostics(client, config, indexerClient, check_connectivity);

      return {
        content: [{ type: "text" as const, text: formatToolResponse(result) }],
        isError: result.status === "error",
      };
    }
  );
}
