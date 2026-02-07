export interface WazuhConfig {
  url: string;
  username: string;
  password: string;
  verifySsl: boolean;
  timeout: number;
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
  const timeout = parseInt(process.env.WAZUH_TIMEOUT ?? "30", 10) * 1000;

  return { url: url.replace(/\/+$/, ""), username, password, verifySsl, timeout };
}
