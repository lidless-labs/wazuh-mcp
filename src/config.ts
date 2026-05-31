export interface WazuhConfig {
  url: string;
  username: string;
  password: string;
  verifySsl: boolean;
  timeout: number;
  indexer?: IndexerConfig;
}

export interface IndexerConfig {
  url: string;
  username: string;
  password: string;
  verifySsl: boolean;
}

function parseTimeoutMs(value: string | undefined): number {
  const timeoutSeconds = Number(value ?? "30");
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new Error("WAZUH_TIMEOUT must be a positive integer number of seconds.");
  }
  return timeoutSeconds * 1000;
}

export function getConfig(): WazuhConfig {
  const url = process.env.WAZUH_URL || process.env.WAZUH_BASE_URL;
  if (!url) {
    throw new Error(
      "WAZUH_URL environment variable is required. Set it to your Wazuh manager API URL (e.g., https://localhost:55000)"
    );
  }

  const username = process.env.WAZUH_USERNAME || process.env.WAZUH_USER;
  if (!username) {
    throw new Error(
      "WAZUH_USERNAME environment variable is required. Set it to your Wazuh API username."
    );
  }

  const password = process.env.WAZUH_PASSWORD;
  if (!password) {
    throw new Error(
      "WAZUH_PASSWORD environment variable is required. Set it to your Wazuh API password."
    );
  }

  const verifySslStr = process.env.WAZUH_VERIFY_SSL ?? "false";
  const verifySsl = verifySslStr.toLowerCase() === "true";
  const timeout = parseTimeoutMs(process.env.WAZUH_TIMEOUT);

  let indexer: IndexerConfig | undefined;
  const indexerUrl = process.env.WAZUH_INDEXER_URL;
  if (indexerUrl) {
    indexer = {
      url: indexerUrl.replace(/\/+$/, ""),
      username: process.env.WAZUH_INDEXER_USERNAME ?? "admin",
      password: process.env.WAZUH_INDEXER_PASSWORD ?? "",
      verifySsl: (process.env.WAZUH_INDEXER_VERIFY_SSL ?? "false").toLowerCase() === "true",
    };
  }

  return { url: url.replace(/\/+$/, ""), username, password, verifySsl, timeout, indexer };
}
