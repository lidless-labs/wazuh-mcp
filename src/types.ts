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

// SCA
export interface WazuhScaPolicy {
  policy_id: string;
  name: string;
  description?: string;
  references?: string;
  hash_file?: string;
  score?: number;
  pass?: number;
  fail?: number;
  invalid?: number;
  total_checks?: number;
  end_scan?: string;
  start_scan?: string;
}

export interface WazuhScaCheck {
  id: number;
  title: string;
  description?: string;
  rationale?: string;
  remediation?: string;
  result: string;
  condition?: string;
  command?: string[];
  references?: string;
  compliance?: Record<string, string[]>;
  rules?: string[];
  file?: string[];
  process?: string[];
  registry?: string[];
  reason?: string;
}

// Syscollector
export interface WazuhOsInfo {
  agent_id?: string;
  name?: string;
  version?: string;
  codename?: string;
  major?: string;
  minor?: string;
  patch?: string;
  build?: string;
  platform?: string;
  sysname?: string;
  hostname?: string;
  release?: string;
  architecture?: string;
  os_name?: string;
  os_version?: string;
}

export interface WazuhPackage {
  name: string;
  version?: string;
  architecture?: string;
  description?: string;
  format?: string;
  vendor?: string;
  install_time?: string;
  location?: string;
  size?: number;
  priority?: string;
  source?: string;
  section?: string;
  multiarch?: string;
}

export interface WazuhProcess {
  pid?: number;
  name?: string;
  state?: string;
  ppid?: number;
  utime?: number;
  stime?: number;
  cmd?: string;
  argvs?: string[];
  euser?: string;
  ruser?: string;
  suser?: string;
  egroup?: string;
  rgroup?: string;
  sgroup?: string;
  fgroup?: string;
  priority?: number;
  nice?: number;
  size?: number;
  vm_size?: number;
  resident?: number;
  share?: number;
  start_time?: number;
  pgrp?: number;
  session?: number;
  nlwp?: number;
  tgid?: number;
  tty?: number;
  processor?: number;
}

export interface WazuhPort {
  protocol?: string;
  local_ip?: string;
  local_port?: number;
  remote_ip?: string;
  remote_port?: number;
  tx_queue?: number;
  rx_queue?: number;
  state?: string;
  pid?: number;
  process?: string;
  inode?: number;
}

export interface WazuhNetIface {
  name?: string;
  adapter?: string;
  type?: string;
  state?: string;
  mtu?: number;
  mac?: string;
  tx_packets?: number;
  rx_packets?: number;
  tx_bytes?: number;
  rx_bytes?: number;
  tx_errors?: number;
  rx_errors?: number;
  tx_dropped?: number;
  rx_dropped?: number;
  ipv4?: Record<string, unknown>;
  ipv6?: Record<string, unknown>;
}

export interface WazuhHotfix {
  hotfix?: string;
}

// Rootcheck
export interface WazuhRootcheckResult {
  status?: string;
  event?: string;
  old_day?: string;
  day?: string;
  cis?: string;
  pci_dss?: string;
}

// Syscheck / FIM
export interface WazuhFimFile {
  file?: string;
  type?: string;
  date?: string;
  mtime?: string;
  size?: number;
  perm?: string;
  uname?: string;
  gname?: string;
  uid?: string;
  gid?: string;
  inode?: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
  changed_attributes?: string[];
  win_attributes?: string;
  attrs?: string;
}

// Manager
export interface WazuhManagerLog {
  timestamp?: string;
  tag?: string;
  level?: string;
  description?: string;
}

// Groups
export interface WazuhGroup {
  name: string;
  count?: number;
  configSum?: string;
  mergedSum?: string;
}
