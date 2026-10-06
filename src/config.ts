import { readFileSync } from "node:fs";

export interface WazuhConfig {
  url: string;
  username: string;
  password: string;
  verifySsl: boolean;
  timeout: number;
  /** PEM CA bundle from WAZUH_CA_FILE, used to verify the manager's certificate. */
  ca?: string;
  indexer?: IndexerConfig;
}

export interface IndexerConfig {
  url: string;
  username: string;
  password: string;
  verifySsl: boolean;
  timeout: number;
  /** PEM CA bundle from WAZUH_INDEXER_CA_FILE, used to verify the indexer's certificate. */
  ca?: string;
}

function parseBooleanEnv(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (["false", "0", "no", "off"].includes(normalized)) return false;
  if (["true", "1", "yes", "on"].includes(normalized)) return true;
  return defaultValue;
}

function optionalCa(ca: string | undefined): { ca?: string } {
  return ca === undefined ? {} : { ca };
}

function parseTimeoutMs(value: string | undefined, envName: string): number {
  const timeoutSeconds = Number(value ?? "30");
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new Error(`${envName} must be a positive integer number of seconds.`);
  }
  return timeoutSeconds * 1000;
}

// Validate a service base URL. Only the origin plus an optional path prefix
// (reverse proxy) is allowed: credentials would leak through logs and
// diagnostics, and a query or fragment would be glued onto every endpoint.
function parseServiceUrl(raw: string, envName: string, allowInsecureHttp: boolean): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${envName} is not a valid URL. Use a form like https://host:port.`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`${envName} must use the https:// scheme (got ${url.protocol}).`);
  }
  if (url.username || url.password) {
    throw new Error(
      `${envName} must not embed credentials. Remove user:password@ from the URL and use the username/password environment variables instead.`
    );
  }
  if (url.search || url.hash || /[?#]/.test(raw)) {
    throw new Error(`${envName} must not contain a query string or fragment.`);
  }
  if (url.protocol === "http:" && !allowInsecureHttp) {
    throw new Error(
      `${envName} uses plain http://, which sends credentials unencrypted. Use https://, or set WAZUH_ALLOW_INSECURE_HTTP=true for a trusted lab network.`
    );
  }
  return raw.replace(/\/+$/, "");
}

function readCaFile(path: string | undefined, envName: string): string | undefined {
  if (!path) return undefined;
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new Error(`${envName} could not be read (${code ?? "unknown error"}): ${path}`);
  }
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
  const allowInsecureHttp = parseBooleanEnv(process.env.WAZUH_ALLOW_INSECURE_HTTP, false);
  const managerUrl = parseServiceUrl(url, process.env.WAZUH_URL ? "WAZUH_URL" : "WAZUH_BASE_URL", allowInsecureHttp);
  const ca = readCaFile(process.env.WAZUH_CA_FILE, "WAZUH_CA_FILE");
  const timeout = parseTimeoutMs(process.env.WAZUH_TIMEOUT, "WAZUH_TIMEOUT");

  let indexer: IndexerConfig | undefined;
  const indexerUrl = process.env.WAZUH_INDEXER_URL;
  if (indexerUrl) {
    const parsedIndexerUrl = parseServiceUrl(indexerUrl, "WAZUH_INDEXER_URL", allowInsecureHttp);
    // Fail fast instead of silently falling back to the indexer superuser
    // name. The account should be a dedicated indexer user with a read-only
    // role.
    const indexerUsername = process.env.WAZUH_INDEXER_USERNAME;
    if (!indexerUsername) {
      throw new Error(
        "WAZUH_INDEXER_USERNAME environment variable is required when WAZUH_INDEXER_URL is set. Set it to a dedicated Wazuh Indexer user with a read-only role, or unset WAZUH_INDEXER_URL to run without alert and vulnerability tools."
      );
    }

    // Fail fast instead of silently defaulting to an empty password and
    // sending "Basic <user>:" on every indexer request.
    const indexerPassword = process.env.WAZUH_INDEXER_PASSWORD;
    if (!indexerPassword) {
      throw new Error(
        "WAZUH_INDEXER_PASSWORD environment variable is required when WAZUH_INDEXER_URL is set. Set it to your Wazuh Indexer password, or unset WAZUH_INDEXER_URL to run without alert and vulnerability tools."
      );
    }

    indexer = {
      url: parsedIndexerUrl,
      username: indexerUsername,
      password: indexerPassword,
      verifySsl: parseBooleanEnv(process.env.WAZUH_INDEXER_VERIFY_SSL, true),
      timeout: parseTimeoutMs(process.env.WAZUH_INDEXER_TIMEOUT, "WAZUH_INDEXER_TIMEOUT"),
      ...optionalCa(readCaFile(process.env.WAZUH_INDEXER_CA_FILE, "WAZUH_INDEXER_CA_FILE")),
    };
  }

  return { url: managerUrl, username, password, verifySsl, timeout, ...optionalCa(ca), indexer };
}
