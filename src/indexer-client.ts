import type { IndexerConfig } from "./config.js";
import { HttpTimeoutError, httpRequest, isTransientNetworkError, type HttpResponse } from "./http.js";
import { extractSafeErrorDetail, safeCaughtErrorMessage, sanitizeErrorMessage } from "./safe-error.js";
import type { WazuhAlert, WazuhVulnerability } from "./types.js";

export class WazuhIndexerError extends Error {
  constructor(
    message: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = "WazuhIndexerError";
  }
}

interface OpenSearchHit {
  _id: string;
  _index: string;
  _source: Record<string, unknown>;
}

interface OpenSearchResponse {
  hits: {
    total: { value: number; relation: string };
    hits: OpenSearchHit[];
  };
}

interface AlertFilters {
  level?: number;
  agent_id?: string;
  rule_id?: string;
  search?: string;
  start_time?: string;
  end_time?: string;
  sortOrder?: "asc" | "desc";
}

interface VulnerabilityFilters {
  cve_id?: string;
  agent_id?: string;
  severity?: string;
  package_name?: string;
  search?: string;
}

export class WazuhIndexerClient {
  private static readonly retryStatuses = new Set([429, 502, 503, 504]);

  private readonly baseUrl: string;
  private readonly authHeader: string;
  private readonly verifySsl: boolean;
  private readonly timeout: number;
  private readonly errorSecrets: string[];

  constructor(config: IndexerConfig) {
    this.baseUrl = config.url;
    this.authHeader =
      "Basic " + Buffer.from(`${config.username}:${config.password}`).toString("base64");
    this.verifySsl = config.verifySsl;
    this.timeout = config.timeout ?? 30_000;
    this.errorSecrets = [config.username, config.password, this.authHeader];
  }

  get tlsVerificationEnabled(): boolean {
    return this.verifySsl;
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  private async send(
    url: string,
    options: {
      method: string;
      headers?: Record<string, string>;
      body?: string;
      retryable?: boolean;
    }
  ): Promise<HttpResponse> {
    const maxAttempts = options.retryable ? 3 : 1;
    let lastError: unknown;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const response = await httpRequest(url, {
          method: options.method,
          headers: options.headers,
          body: options.body,
          timeoutMs: this.timeout,
          verifySsl: this.verifySsl,
        });
        if (
          attempt < maxAttempts &&
          WazuhIndexerClient.retryStatuses.has(response.status)
        ) {
          await this.sleep(100 * attempt);
          continue;
        }
        return response;
      } catch (error) {
        if (error instanceof HttpTimeoutError) {
          throw new WazuhIndexerError(`Wazuh Indexer request timeout after ${this.timeout}ms`);
        }
        lastError = error;
        if (attempt >= maxAttempts || !isTransientNetworkError(error)) {
          throw new WazuhIndexerError(
            `Wazuh Indexer request failed: ${safeCaughtErrorMessage(error, "network error", this.errorSecrets)}`
          );
        }
        await this.sleep(100 * attempt);
      }
    }

    throw new WazuhIndexerError(
      `Wazuh Indexer request failed: ${safeCaughtErrorMessage(lastError, "network error", this.errorSecrets)}`
    );
  }

  private async fetchJson<T>(
    path: string,
    init: {
      method: string;
      headers?: Record<string, string>;
      body?: string;
      retryable?: boolean;
    }
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.send(url, init);

    if (!response.ok) {
      const errorBody = await response.json().catch(() => null);
      const detail = extractSafeErrorDetail(errorBody, this.errorSecrets);
      const errorMsg = `${response.status} ${sanitizeErrorMessage(response.statusText, this.errorSecrets)}${detail ? `: ${detail}` : ""}`;
      throw new WazuhIndexerError(`Indexer request failed: ${errorMsg}`, response.status);
    }

    return (await response.json()) as T;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.fetchJson<T>(path, {
      method: "POST",
      headers: {
        Authorization: this.authHeader,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      retryable: true,
    });
  }

  async getInfo(): Promise<Record<string, unknown>> {
    return this.fetchJson<Record<string, unknown>>("/", {
      method: "GET",
      headers: {
        Authorization: this.authHeader,
      },
      retryable: true,
    });
  }

  async indexExists(indexPattern: string): Promise<boolean> {
    const path = `/${encodeURIComponent(indexPattern).replaceAll("%2A", "*")}`;
    const url = `${this.baseUrl}${path}`;
    const response = await this.send(url, {
      method: "HEAD",
      headers: {
        Authorization: this.authHeader,
      },
      retryable: true,
    });

    if (response.status === 404) return false;
    if (!response.ok) {
      throw new WazuhIndexerError(
        `Indexer request failed: ${response.status} ${sanitizeErrorMessage(response.statusText, this.errorSecrets)}`,
        response.status
      );
    }
    return true;
  }

  private mapHitToAlert(hit: OpenSearchHit): WazuhAlert {
    const s = hit._source as Record<string, unknown>;
    const rule = s.rule as Record<string, unknown> | undefined;
    const agent = s.agent as Record<string, unknown> | undefined;
    const manager = s.manager as Record<string, unknown> | undefined;
    const decoder = s.decoder as Record<string, unknown> | undefined;
    const mitre = rule?.mitre as Record<string, unknown> | undefined;

    return {
      id: hit._id,
      timestamp: s.timestamp as string,
      rule: rule
        ? {
            id: rule.id as string | undefined,
            level: rule.level as number | undefined,
            description: rule.description as string | undefined,
            groups: rule.groups as string[] | undefined,
            pci_dss: rule.pci_dss as string[] | undefined,
            gdpr: rule.gdpr as string[] | undefined,
            hipaa: rule.hipaa as string[] | undefined,
            nist_800_53: rule.nist_800_53 as string[] | undefined,
            mitre: mitre
              ? {
                  id: mitre.id as string[] | undefined,
                  tactic: mitre.tactic as string[] | undefined,
                  technique: mitre.technique as string[] | undefined,
                }
              : undefined,
          }
        : undefined,
      agent: agent
        ? {
            id: agent.id as string | undefined,
            name: agent.name as string | undefined,
            ip: agent.ip as string | undefined,
          }
        : undefined,
      manager: manager ? { name: manager.name as string | undefined } : undefined,
      location: s.location as string | undefined,
      decoder: decoder ? { name: decoder.name as string | undefined } : undefined,
      full_log: s.full_log as string | undefined,
      data: s.data as Record<string, unknown> | undefined,
    };
  }

  private mapHitToVulnerability(hit: OpenSearchHit): WazuhVulnerability {
    const s = hit._source as Record<string, unknown>;
    const agent = s.agent as Record<string, unknown> | undefined;
    const host = s.host as Record<string, unknown> | undefined;
    const hostOs = host?.os as Record<string, unknown> | undefined;
    const pkg = s.package as Record<string, unknown> | undefined;
    const vulnerability = s.vulnerability as Record<string, unknown> | undefined;
    const score = vulnerability?.score as Record<string, unknown> | undefined;

    return {
      id: hit._id,
      agent: agent
        ? {
            id: agent.id as string | undefined,
            name: agent.name as string | undefined,
            version: agent.version as string | undefined,
          }
        : undefined,
      host: hostOs
        ? {
            os: {
              full: hostOs.full as string | undefined,
              kernel: hostOs.kernel as string | undefined,
              name: hostOs.name as string | undefined,
              platform: hostOs.platform as string | undefined,
              type: hostOs.type as string | undefined,
              version: hostOs.version as string | undefined,
            },
          }
        : undefined,
      package: pkg
        ? {
            architecture: pkg.architecture as string | undefined,
            description: pkg.description as string | undefined,
            installed: pkg.installed as string | undefined,
            name: pkg.name as string | undefined,
            size: pkg.size as number | undefined,
            type: pkg.type as string | undefined,
            version: pkg.version as string | undefined,
          }
        : undefined,
      vulnerability: vulnerability
        ? {
            category: vulnerability.category as string | undefined,
            classification: vulnerability.classification as string | undefined,
            description: vulnerability.description as string | undefined,
            detected_at: vulnerability.detected_at as string | undefined,
            enumeration: vulnerability.enumeration as string | undefined,
            id: vulnerability.id as string | undefined,
            published_at: vulnerability.published_at as string | undefined,
            reference: vulnerability.reference as string | undefined,
            score: score
              ? {
                  base: score.base as number | undefined,
                  version: score.version as string | undefined,
                }
              : undefined,
            severity: vulnerability.severity as string | undefined,
          }
        : undefined,
    };
  }

  async searchAlerts(
    query: Record<string, unknown>,
    size: number,
    from: number,
    sortOrder: "asc" | "desc" = "desc"
  ): Promise<{ alerts: WazuhAlert[]; total: number }> {
    const body = {
      query,
      size,
      from,
      sort: [{ timestamp: { order: sortOrder } }],
      track_total_hits: true,
    };

    const result = await this.post<OpenSearchResponse>("/wazuh-alerts-*/_search", body);
    return {
      alerts: result.hits.hits.map((h) => this.mapHitToAlert(h)),
      total: result.hits.total.value,
    };
  }

  async getRecentAlerts(
    limit: number,
    offset: number,
    filters?: AlertFilters
  ): Promise<{ alerts: WazuhAlert[]; total: number }> {
    const must: unknown[] = [];

    if (filters?.level !== undefined) {
      must.push({ range: { "rule.level": { gte: filters.level } } });
    }
    if (filters?.agent_id) {
      must.push({ term: { "agent.id": filters.agent_id } });
    }
    if (filters?.rule_id) {
      must.push({ term: { "rule.id": filters.rule_id } });
    }
    if (filters?.search) {
      must.push({
        multi_match: {
          query: filters.search,
          fields: ["full_log", "rule.description", "agent.name"],
          type: "best_fields",
        },
      });
    }
    if (filters?.start_time || filters?.end_time) {
      const timestampRange: Record<string, string> = {};
      if (filters.start_time) timestampRange.gte = filters.start_time;
      if (filters.end_time) timestampRange.lte = filters.end_time;
      must.push({ range: { timestamp: timestampRange } });
    }

    const query = must.length > 0 ? { bool: { must } } : { match_all: {} };
    return this.searchAlerts(query, limit, offset, filters?.sortOrder);
  }

  async getAlert(id: string): Promise<WazuhAlert | null> {
    const body = {
      query: { ids: { values: [id] } },
      size: 1,
      track_total_hits: true,
    };

    const result = await this.post<OpenSearchResponse>("/wazuh-alerts-*/_search", body);
    if (result.hits.hits.length === 0) return null;
    return this.mapHitToAlert(result.hits.hits[0]);
  }

  async fullTextSearch(
    query: string,
    limit: number,
    offset: number,
    filters?: AlertFilters
  ): Promise<{ alerts: WazuhAlert[]; total: number }> {
    const must: unknown[] = [
      {
        multi_match: {
          query,
          fields: ["full_log", "rule.description", "agent.name"],
          type: "best_fields",
        },
      },
    ];

    if (filters?.level !== undefined) {
      must.push({ range: { "rule.level": { gte: filters.level } } });
    }
    if (filters?.agent_id) {
      must.push({ term: { "agent.id": filters.agent_id } });
    }
    if (filters?.start_time || filters?.end_time) {
      const timestampRange: Record<string, string> = {};
      if (filters.start_time) timestampRange.gte = filters.start_time;
      if (filters.end_time) timestampRange.lte = filters.end_time;
      must.push({ range: { timestamp: timestampRange } });
    }

    return this.searchAlerts({ bool: { must } }, limit, offset);
  }

  async searchVulnerabilities(
    limit: number,
    offset: number,
    filters: VulnerabilityFilters = {}
  ): Promise<{ vulnerabilities: WazuhVulnerability[]; total: number }> {
    const must: unknown[] = [];

    if (filters.cve_id) {
      must.push({ term: { "vulnerability.id": filters.cve_id } });
    }
    if (filters.agent_id) {
      must.push({ term: { "agent.id": filters.agent_id } });
    }
    if (filters.severity) {
      must.push({ term: { "vulnerability.severity": filters.severity } });
    }
    if (filters.package_name) {
      must.push({ match: { "package.name": filters.package_name } });
    }
    if (filters.search) {
      must.push({
        multi_match: {
          query: filters.search,
          fields: ["vulnerability.id", "vulnerability.description", "package.name", "agent.name"],
          type: "best_fields",
        },
      });
    }

    const body = {
      query: must.length > 0 ? { bool: { must } } : { match_all: {} },
      size: limit,
      from: offset,
      sort: [{ "vulnerability.detected_at": { order: "desc", unmapped_type: "date" } }],
      track_total_hits: true,
    };

    const result = await this.post<OpenSearchResponse>("/wazuh-states-vulnerabilities*/_search", body);
    return {
      vulnerabilities: result.hits.hits.map((h) => this.mapHitToVulnerability(h)),
      total: result.hits.total.value,
    };
  }
}
