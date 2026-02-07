// Wazuh API response wrapper
export interface WazuhApiResponse<T> {
  data: T;
  error: number;
  message: string;
}

// Wazuh paginated data wrapper
export interface WazuhPaginatedData<T> {
  affected_items: T[];
  total_affected_items: number;
  failed_items: unknown[];
  total_failed_items: number;
}

// Authentication
export interface WazuhTokenData {
  token: string;
}

// Version
export interface WazuhVersionInfo {
  title: string;
  api_version: string;
  revision: number;
  license_name: string;
  license_url: string;
  hostname: string;
  timestamp: string;
}

// Agent
export interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: string;
  group?: string[];
  os?: {
    name?: string;
    version?: string;
    platform?: string;
    arch?: string;
    codename?: string;
  };
  version?: string;
  manager?: string;
  node_name?: string;
  dateAdd?: string;
  lastKeepAlive?: string;
  registerIP?: string;
  status_code?: number;
}

// Agent stats
export interface WazuhAgentStats {
  cpu?: {
    usage_percent?: number;
    load_average?: number[];
    cores?: number;
  };
  memory?: {
    total_bytes?: number;
    used_bytes?: number;
    free_bytes?: number;
    usage_percent?: number;
  };
  disk?: Array<{
    path?: string;
    total_bytes?: number;
    used_bytes?: number;
    free_bytes?: number;
    usage_percent?: number;
  }>;
}

// Alert
export interface WazuhAlert {
  id?: string;
  timestamp: string;
  rule?: {
    id?: string;
    level?: number;
    description?: string;
    groups?: string[];
    pci_dss?: string[];
    gdpr?: string[];
    hipaa?: string[];
    nist_800_53?: string[];
    mitre?: {
      id?: string[];
      tactic?: string[];
      technique?: string[];
    };
  };
  agent?: {
    id?: string;
    name?: string;
    ip?: string;
  };
  manager?: {
    name?: string;
  };
  location?: string;
  decoder?: {
    name?: string;
  };
  full_log?: string;
  data?: Record<string, unknown>;
}

// Rule
export interface WazuhRule {
  id: number;
  description: string;
  level: number;
  groups?: string[];
  pci_dss?: string[];
  gdpr?: string[];
  gpg13?: string[];
  hipaa?: string[];
  nist_800_53?: string[];
  tsc?: string[];
  mitre?: {
    id?: string[];
    tactic?: string[];
    technique?: string[];
  };
  details?: Record<string, unknown>;
  filename?: string;
  relative_dirname?: string;
  status?: string;
}

// Decoder
export interface WazuhDecoder {
  name: string;
  details?: Record<string, unknown>;
  filename?: string;
  relative_dirname?: string;
  status?: string;
  position?: number;
}
