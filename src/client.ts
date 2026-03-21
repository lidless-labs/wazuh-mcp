import type { WazuhConfig } from "./config.js";
import type {
  WazuhApiResponse,
  WazuhPaginatedData,
  WazuhAgent,
  WazuhAgentStats,
  WazuhAlert,
  WazuhRule,
  WazuhDecoder,
  WazuhVersionInfo,
  WazuhTokenData,
  WazuhScaPolicy,
  WazuhScaCheck,
  WazuhOsInfo,
  WazuhPackage,
  WazuhProcess,
  WazuhPort,
  WazuhNetIface,
  WazuhHotfix,
  WazuhRootcheckResult,
  WazuhFimFile,
  WazuhManagerLog,
  WazuhGroup,
} from "./types.js";

export class WazuhClientError extends Error {
  constructor(
    message: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = "WazuhClientError";
  }
}

export class WazuhAuthenticationError extends WazuhClientError {
  constructor(message: string, statusCode?: number) {
    super(message, statusCode);
    this.name = "WazuhAuthenticationError";
  }
}

export class WazuhClient {
  private token: string | null = null;
  private readonly baseUrl: string;
  private readonly username: string;
  private readonly password: string;
  private readonly verifySsl: boolean;
  private readonly timeout: number;

  constructor(config: WazuhConfig) {
    this.baseUrl = config.url;
    this.username = config.username;
    this.password = config.password;
    this.verifySsl = config.verifySsl;
    this.timeout = config.timeout;
  }

  private get fetchOptions(): RequestInit {
    const opts: RequestInit = {};
    if (!this.verifySsl) {
      // Node 20+ supports this via the dispatcher option on undici,
      // but for standard fetch we rely on NODE_TLS_REJECT_UNAUTHORIZED=0
      // which is set at startup in index.ts
    }
    return opts;
  }

  private createAbortSignal(): { signal: AbortSignal; clear: () => void } {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    return {
      signal: controller.signal,
      clear: () => clearTimeout(timeoutId),
    };
  }

  async authenticate(): Promise<string> {
    const credentials = Buffer.from(
      `${this.username}:${this.password}`
    ).toString("base64");

    const { signal, clear } = this.createAbortSignal();
    let response: Response;
    try {
      response = await fetch(
        `${this.baseUrl}/security/user/authenticate`,
        {
          method: "POST",
          headers: {
            Authorization: `Basic ${credentials}`,
            "Content-Type": "application/json",
          },
          signal,
          ...this.fetchOptions,
        }
      );
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new WazuhClientError(`Wazuh API authentication timeout after ${this.timeout}ms`);
      }
      throw error;
    } finally {
      clear();
    }

    if (!response.ok) {
      throw new WazuhAuthenticationError(
        `Authentication failed: ${response.status} ${response.statusText}`,
        response.status
      );
    }

    const body = (await response.json()) as WazuhApiResponse<WazuhTokenData>;
    if (!body.data?.token) {
      throw new WazuhAuthenticationError(
        "Authentication response missing token"
      );
    }

    this.token = body.data.token;
    return this.token;
  }

  private async ensureAuthenticated(): Promise<void> {
    if (!this.token) {
      await this.authenticate();
    }
  }

  async request<T>(
    method: string,
    endpoint: string,
    params?: Record<string, string | number>,
    body?: unknown
  ): Promise<T> {
    await this.ensureAuthenticated();

    const url = new URL(`${this.baseUrl}${endpoint}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.token}`,
      "Content-Type": "application/json",
    };

    const { signal, clear } = this.createAbortSignal();
    let response: Response;
    try {
      response = await fetch(url.toString(), {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal,
        ...this.fetchOptions,
      });
    } catch (error) {
      clear();
      if (error instanceof Error && error.name === "AbortError") {
        throw new WazuhClientError(`Wazuh API timeout after ${this.timeout}ms`);
      }
      throw error;
    }
    clear();

    // Auto-refresh token on 401
    if (response.status === 401) {
      this.token = null;
      await this.authenticate();
      headers.Authorization = `Bearer ${this.token}`;

      const { signal: retrySignal, clear: retryClear } = this.createAbortSignal();
      let retryResponse: Response;
      try {
        retryResponse = await fetch(url.toString(), {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: retrySignal,
          ...this.fetchOptions,
        });
      } catch (error) {
        retryClear();
        if (error instanceof Error && error.name === "AbortError") {
          throw new WazuhClientError(`Wazuh API timeout after ${this.timeout}ms`);
        }
        throw error;
      }
      retryClear();

      if (!retryResponse.ok) {
        throw new WazuhClientError(
          `Request failed after re-auth: ${retryResponse.status} ${retryResponse.statusText}`,
          retryResponse.status
        );
      }

      return (await retryResponse.json()) as T;
    }

    if (!response.ok) {
      let errorMsg = `${response.status} ${response.statusText}`;
      try {
        const errorBody = await response.json();
        if (errorBody.message) {
          errorMsg = `${errorMsg}: ${errorBody.message}`;
        }
      } catch {
        // ignore JSON parse errors on error responses
      }
      throw new WazuhClientError(`Request failed: ${errorMsg}`, response.status);
    }

    return (await response.json()) as T;
  }

  async get<T>(
    endpoint: string,
    params?: Record<string, string | number>
  ): Promise<T> {
    return this.request<T>("GET", endpoint, params);
  }

  // --- Agent methods ---

  async getAgents(
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhAgent>>> {
    return this.get("/agents", params);
  }

  async getAgent(
    agentId: string
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhAgent>>> {
    return this.get(`/agents`, { agents_list: agentId });
  }

  async getAgentStats(
    agentId: string
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhAgentStats>>> {
    return this.get(`/agents/${agentId}/stats/agent`);
  }

  // --- Alert methods ---

  async getAlerts(
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhAlert>>> {
    return this.get("/alerts", params);
  }

  // --- Rule methods ---

  async getRules(
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhRule>>> {
    return this.get("/rules", params);
  }

  async getRule(
    ruleId: number
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhRule>>> {
    return this.get("/rules", { rule_ids: ruleId });
  }

  // --- Decoder methods ---

  async getDecoders(
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhDecoder>>> {
    return this.get("/decoders", params);
  }

  // --- Version method ---

  async getVersion(): Promise<WazuhApiResponse<WazuhVersionInfo>> {
    return this.get("/");
  }

  // --- SCA methods ---

  async getScaPolicies(
    agentId: string
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhScaPolicy>>> {
    return this.get(`/sca/${agentId}`);
  }

  async getScaChecks(
    agentId: string,
    policyId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhScaCheck>>> {
    return this.get(`/sca/${agentId}/checks/${policyId}`, params);
  }

  // --- Syscollector methods ---

  async getAgentOs(
    agentId: string
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhOsInfo>>> {
    return this.get(`/syscollector/${agentId}/os`);
  }

  async getAgentPackages(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhPackage>>> {
    return this.get(`/syscollector/${agentId}/packages`, params);
  }

  async getAgentProcesses(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhProcess>>> {
    return this.get(`/syscollector/${agentId}/processes`, params);
  }

  async getAgentPorts(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhPort>>> {
    return this.get(`/syscollector/${agentId}/ports`, params);
  }

  async getAgentNetwork(
    agentId: string
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhNetIface>>> {
    return this.get(`/syscollector/${agentId}/netiface`);
  }

  async getAgentHotfixes(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhHotfix>>> {
    return this.get(`/syscollector/${agentId}/hotfixes`, params);
  }

  // --- Rootcheck methods ---

  async getRootcheck(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhRootcheckResult>>> {
    return this.get(`/rootcheck/${agentId}`, params);
  }

  // --- Syscheck / FIM methods ---

  async getFimFiles(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhFimFile>>> {
    return this.get(`/syscheck/${agentId}`, params);
  }

  // --- Manager methods ---

  async getManagerLogs(
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhManagerLog>>> {
    return this.get("/manager/logs", params);
  }

  async getManagerConfig(
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<Record<string, unknown>>> {
    return this.get("/manager/configuration", params);
  }

  // --- Group methods ---

  async getGroups(
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhGroup>>> {
    return this.get("/groups", params);
  }

  async getGroupAgents(
    groupId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhAgent>>> {
    return this.get(`/groups/${groupId}/agents`, params);
  }
}
