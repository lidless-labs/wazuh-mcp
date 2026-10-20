import { isIP } from "node:net";
import tls, { type PeerCertificate } from "node:tls";

const MAX_NAME_LENGTH = 253;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export interface TlsIdentityOptions {
  /** SNI name. Present only when the configured identity is a DNS name. */
  servername?: string;
  checkServerIdentity: (hostname: string, cert: PeerCertificate) => Error | undefined;
}

/**
 * Validate a WAZUH_TLS_SERVERNAME / WAZUH_INDEXER_TLS_SERVERNAME value.
 * Accepts a bare IPv4 address, IPv6 address, or DNS name. Returns undefined
 * when the variable is unset. The offending value is never echoed back.
 */
export function parseTlsServername(raw: string | undefined, envName: string): string | undefined {
  if (raw === undefined) return undefined;
  const value = raw.trim();
  if (value.length === 0) {
    throw new Error(`${envName} must not be empty. Unset it to use the host from the service URL.`);
  }
  if (value.length > MAX_NAME_LENGTH) {
    throw new Error(`${envName} must be at most ${MAX_NAME_LENGTH} characters.`);
  }
  if (value.includes("://")) {
    throw new Error(`${envName} must be a bare host name or IP address without a scheme.`);
  }
  if (/[/?#@\s]/.test(value)) {
    throw new Error(`${envName} must be a bare host name or IP address without a path, query, credentials, or spaces.`);
  }
  if (isIP(value) !== 0) return value.toLowerCase();

  if (value.includes(":") || value.includes("[") || value.includes("]")) {
    throw new Error(`${envName} must not include a port or brackets. Use a bare host name or IP address.`);
  }
  const name = value.toLowerCase();
  const labels = name.split(".");
  const validLabels = labels.every((label) => DNS_LABEL.test(label));
  // An all-numeric last label means a malformed IPv4 address, not a DNS name.
  const lastLabelNumeric = /^[0-9]+$/.test(labels[labels.length - 1] ?? "");
  if (!validLabels || lastLabelNumeric) {
    throw new Error(`${envName} must be a valid IPv4 address, IPv6 address, or DNS name.`);
  }
  return name;
}

/**
 * TLS options that check the peer certificate identity against `servername`
 * instead of the host in the request URL. Chain validation is unchanged: it
 * still runs first, and this hook only replaces the identity comparison.
 * SNI is set only for DNS names, because Node rejects an IP address there.
 */
export function buildTlsIdentityOptions(servername: string): TlsIdentityOptions {
  return {
    ...(isIP(servername) === 0 ? { servername } : {}),
    checkServerIdentity: (_hostname, cert) => tls.checkServerIdentity(servername, cert),
  };
}
