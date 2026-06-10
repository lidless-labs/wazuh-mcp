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
  timeout: number;
}

function parseBooleanEnv(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (["false", "0", "no", "off"].includes(normalized)) return false;
  if (["true", "1", "yes", "on"].includes(normalized)) return true;
  return defaultValue;
}

function parseTimeoutMs(value: string | undefined, envName: string): number {
  const timeoutSeconds = Number(value ?? "30");
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new Error(`${envName} must be a positive integer number of seconds.`);
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

  // Secure by default: verify TLS certificates unless the operator explicitly
  // opts out (e.g. WAZUH_VERIFY_SSL=false/0/no/off for trusted self-signed labs).
  const verifySsl = parseBooleanEnv(process.env.WAZUH_VERIFY_SSL, true);
  const timeout = parseTimeoutMs(process.env.WAZUH_TIMEOUT, "WAZUH_TIMEOUT");

  let indexer: IndexerConfig | undefined;
  const indexerUrl = process.env.WAZUH_INDEXER_URL;
  if (indexerUrl) {
    // Fail fast instead of silently defaulting to an empty password and
    // sending "Basic admin:" on every indexer request.
    const indexerPassword = process.env.WAZUH_INDEXER_PASSWORD;
    if (!indexerPassword) {
      throw new Error(
        "WAZUH_INDEXER_PASSWORD environment variable is required when WAZUH_INDEXER_URL is set. Set it to your Wazuh Indexer password, or unset WAZUH_INDEXER_URL to run without alert and vulnerability tools."
      );
    }

    indexer = {
      url: indexerUrl.replace(/\/+$/, ""),
      username: process.env.WAZUH_INDEXER_USERNAME ?? "admin",
      password: indexerPassword,
      verifySsl: parseBooleanEnv(process.env.WAZUH_INDEXER_VERIFY_SSL, true),
      timeout: parseTimeoutMs(process.env.WAZUH_INDEXER_TIMEOUT, "WAZUH_INDEXER_TIMEOUT"),
    };
  }

  return { url: url.replace(/\/+$/, ""), username, password, verifySsl, timeout, indexer };
}
