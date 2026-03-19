import type { IndexerConfig } from "./config.js";
import type { WazuhAlert } from "./types.js";

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

  private async post<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const { signal, clear } = this.createAbortSignal();
    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: this.authHeader,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
        signal,
      });
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

  async searchAlerts(query: Record<string, unknown>, size: number, from: number): Promise<{ alerts: WazuhAlert[]; total: number }> {
    const body = {
      query,
      size,
      from,
      sort: [{ timestamp: { order: "desc" } }],
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
    filters?: {
      level?: number;
      agent_id?: string;
      rule_id?: string;
      search?: string;
    }
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
        },
      });
    }

    const query = must.length > 0 ? { bool: { must } } : { match_all: {} };
    return this.searchAlerts(query, limit, offset);
  }

  async getAlert(id: string): Promise<WazuhAlert | null> {
    const body = {
      query: { ids: { values: [id] } },
      size: 1,
    };

    const result = await this.post<OpenSearchResponse>("/wazuh-alerts-*/_search", body);
    if (result.hits.hits.length === 0) return null;
    return this.mapHitToAlert(result.hits.hits[0]);
  }

  async fullTextSearch(
    query: string,
    limit: number,
    offset: number,
    filters?: { level?: number; agent_id?: string }
  ): Promise<{ alerts: WazuhAlert[]; total: number }> {
    const must: unknown[] = [
      {
        multi_match: {
          query,
          fields: ["full_log", "rule.description", "agent.name"],
        },
      },
    ];

    if (filters?.level !== undefined) {
      must.push({ range: { "rule.level": { gte: filters.level } } });
    }
    if (filters?.agent_id) {
      must.push({ term: { "agent.id": filters.agent_id } });
    }

    return this.searchAlerts({ bool: { must } }, limit, offset);
  }
}
