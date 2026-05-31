import type { IndexerConfig } from "./config.js";
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
  private readonly baseUrl: string;
  private readonly authHeader: string;
  private readonly verifySsl: boolean;
  private readonly timeout = 30_000;

  constructor(config: IndexerConfig) {
    this.baseUrl = config.url;
    this.authHeader =
      "Basic " + Buffer.from(`${config.username}:${config.password}`).toString("base64");
    this.verifySsl = config.verifySsl;
  }

  private createAbortSignal(): { signal: AbortSignal; clear: () => void } {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    return { signal: controller.signal, clear: () => clearTimeout(timeoutId) };
  }

  get tlsVerificationEnabled(): boolean {
    return this.verifySsl;
  }

  private async fetchJson<T>(path: string, init: RequestInit): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const { signal, clear } = this.createAbortSignal();
    let response: Response;
    try {
      response = await fetch(url, { ...init, signal });
    } catch (error) {
      clear();
      if (error instanceof Error && error.name === "AbortError") {
        throw new WazuhIndexerError(`Wazuh Indexer request timeout after ${this.timeout}ms`);
      }
      throw error;
    }
    clear();

    if (!response.ok) {
      let errorMsg = `${response.status} ${response.statusText}`;
      try {
        const errorBody = (await response.json()) as Record<string, unknown>;
        if (errorBody.error) {
          errorMsg = `${errorMsg}: ${JSON.stringify(errorBody.error)}`;
        }
      } catch {
        // ignore JSON parse errors
      }
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
    });
  }

  async getInfo(): Promise<Record<string, unknown>> {
    return this.fetchJson<Record<string, unknown>>("/", {
      method: "GET",
      headers: {
        Authorization: this.authHeader,
      },
    });
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
