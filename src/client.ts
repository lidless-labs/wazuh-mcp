import type { WazuhConfig } from "./config.js";
import { HttpTimeoutError, httpRequest, isTransientNetworkError, type HttpResponse } from "./http.js";
import { extractSafeErrorDetail, safeCaughtErrorMessage, sanitizeErrorMessage } from "./safe-error.js";
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
  private static readonly retryStatuses = new Set([429, 502, 503, 504]);

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

  private get errorSecrets(): string[] {
    return [this.username, this.password, this.token ?? ""];
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
          WazuhClient.retryStatuses.has(response.status)
        ) {
          await this.sleep(100 * attempt);
          continue;
        }
        return response;
      } catch (error) {
        if (error instanceof HttpTimeoutError) {
          throw new WazuhClientError(`Wazuh API timeout after ${this.timeout}ms`);
        }
        lastError = error;
        if (attempt >= maxAttempts || !isTransientNetworkError(error)) {
          throw new WazuhClientError(
            `Wazuh API request failed: ${safeCaughtErrorMessage(error, "network error", this.errorSecrets)}`
          );
        }
        await this.sleep(100 * attempt);
      }
    }

    throw new WazuhClientError(
      `Wazuh API request failed: ${safeCaughtErrorMessage(lastError, "network error", this.errorSecrets)}`
    );
  }

  private pathSegment(value: string): string {
    return encodeURIComponent(value);
  }

  async authenticate(): Promise<string> {
    const credentials = Buffer.from(
      `${this.username}:${this.password}`
    ).toString("base64");

    let response: HttpResponse;
    try {
      response = await this.send(`${this.baseUrl}/security/user/authenticate`, {
        method: "POST",
        headers: {
          Authorization: `Basic ${credentials}`,
          "Content-Type": "application/json",
        },
      });
    } catch (error) {
      if (error instanceof WazuhClientError) {
        if (error.message.includes("timeout")) {
          throw new WazuhClientError(`Wazuh API authentication timeout after ${this.timeout}ms`);
        }
        throw error;
      }
      if (error instanceof Error && error.name === "AbortError") {
        throw new WazuhClientError(`Wazuh API authentication timeout after ${this.timeout}ms`);
      }
      throw error;
    }

    if (!response.ok) {
      throw new WazuhAuthenticationError(
        `Authentication failed: ${response.status} ${sanitizeErrorMessage(response.statusText, this.errorSecrets)}`,
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

    const response = await this.send(url.toString(), {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      retryable: method === "GET",
    });

    // Auto-refresh token on 401
    if (response.status === 401) {
      this.token = null;
      await this.authenticate();
      headers.Authorization = `Bearer ${this.token}`;

      const retryResponse = await this.send(url.toString(), {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        retryable: method === "GET",
      });

      if (!retryResponse.ok) {
        const detail = extractSafeErrorDetail(await retryResponse.json().catch(() => null), this.errorSecrets);
        throw new WazuhClientError(
          `Request failed after re-auth: ${retryResponse.status} ${sanitizeErrorMessage(retryResponse.statusText, this.errorSecrets)}${detail ? `: ${detail}` : ""}`,
          retryResponse.status
        );
      }

      return (await retryResponse.json()) as T;
    }

    if (!response.ok) {
      const errorBody = await response.json().catch(() => null);
      const detail = extractSafeErrorDetail(errorBody, this.errorSecrets);
      const errorMsg = `${response.status} ${sanitizeErrorMessage(response.statusText, this.errorSecrets)}${detail ? `: ${detail}` : ""}`;
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
    return this.get(`/agents/${this.pathSegment(agentId)}/stats/agent`);
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
    return this.get(`/sca/${this.pathSegment(agentId)}`);
  }

  async getScaChecks(
    agentId: string,
    policyId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhScaCheck>>> {
    return this.get(
      `/sca/${this.pathSegment(agentId)}/checks/${this.pathSegment(policyId)}`,
      params
    );
  }

  // --- Syscollector methods ---

  async getAgentOs(
    agentId: string
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhOsInfo>>> {
    return this.get(`/syscollector/${this.pathSegment(agentId)}/os`);
  }

  async getAgentPackages(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhPackage>>> {
    return this.get(`/syscollector/${this.pathSegment(agentId)}/packages`, params);
  }

  async getAgentProcesses(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhProcess>>> {
    return this.get(`/syscollector/${this.pathSegment(agentId)}/processes`, params);
  }

  async getAgentPorts(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhPort>>> {
    return this.get(`/syscollector/${this.pathSegment(agentId)}/ports`, params);
  }

  async getAgentNetwork(
    agentId: string
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhNetIface>>> {
    return this.get(`/syscollector/${this.pathSegment(agentId)}/netiface`);
  }

  async getAgentHotfixes(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhHotfix>>> {
    return this.get(`/syscollector/${this.pathSegment(agentId)}/hotfixes`, params);
  }

  // --- Rootcheck methods ---

  async getRootcheck(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhRootcheckResult>>> {
    return this.get(`/rootcheck/${this.pathSegment(agentId)}`, params);
  }

  // --- Syscheck / FIM methods ---

  async getFimFiles(
    agentId: string,
    params: Record<string, string | number> = {}
  ): Promise<WazuhApiResponse<WazuhPaginatedData<WazuhFimFile>>> {
    return this.get(`/syscheck/${this.pathSegment(agentId)}`, params);
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
    return this.get(`/groups/${this.pathSegment(groupId)}/agents`, params);
  }
}
