<p align="center">
  <img src="docs/assets/wazuh-mcp-banner.jpg" alt="wazuh-mcp banner">
</p>

<h1 align="center">wazuh-mcp</h1>

<p align="center">
  <strong>MCP server for Wazuh SIEM/XDR platform integration.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/solomonneas/wazuh-mcp/ci.yml?branch=main&style=for-the-badge&label=CI&logo=githubactions&logoColor=white" alt="CI status">
  <img src="https://img.shields.io/npm/v/wazuh-mcp?style=for-the-badge&logo=npm&logoColor=white" alt="npm version">
  <img src="https://img.shields.io/badge/typescript-6.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript 6.0">
  <img src="https://img.shields.io/badge/node.js-20%2B-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js 20+">
  <img src="https://img.shields.io/badge/MCP-SDK_1.29-7c3aed?style=for-the-badge" alt="MCP SDK 1.29">
  <img src="https://img.shields.io/badge/Wazuh-SIEM%2FXDR-3385ff?style=for-the-badge" alt="Wazuh SIEM/XDR">
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-mapped-0f766e?style=for-the-badge" alt="MITRE ATT&CK mapped">
  <img src="https://img.shields.io/badge/Vitest-4-6E9F18?style=for-the-badge&logo=vitest&logoColor=white" alt="Vitest 4">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="MIT License">
</p>

A [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for the [Wazuh](https://wazuh.com/) SIEM/XDR platform. Query agents, security alerts, detection rules, and decoders directly from Claude or any MCP-compatible client.

## Features

- **26 MCP Tools** - Agents, alerts, rules, decoders, SCA, syscollector, FIM, rootcheck, groups, manager, and diagnostics
- **3 MCP Resources** - Pre-built views for agents, recent alerts, and rule summaries
- **3 MCP Prompts** - Alert investigation, agent health checks, and security overviews
- **JWT Authentication** - Automatic token management with refresh on expiry
- **Full Compliance Mapping** - PCI-DSS, GDPR, HIPAA, NIST 800-53, MITRE ATT&CK
- **Pagination** - All list endpoints support limit/offset pagination
- **Type-Safe** - Full TypeScript with strict mode and Zod schema validation

## Prerequisites

- Node.js 20+
<!-- content-guard: allow port-reference -->
- A running Wazuh manager with API access (default port 55000)
- Wazuh API credentials (username/password)
- (Optional) Wazuh Indexer (OpenSearch) access for alert queries

## Installation

```bash
git clone https://github.com/solomonneas/wazuh-mcp.git
cd wazuh-mcp
npm install
npm run build
```

## Configuration

Set the following environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
<!-- content-guard: allow private-ipv4 -->
| `WAZUH_URL` | Yes | - | Wazuh API URL (e.g., `https://10.0.0.2:55000`) |
| `WAZUH_USERNAME` | Yes | - | API username |
| `WAZUH_PASSWORD` | Yes | - | API password |
| `WAZUH_VERIFY_SSL` | No | `false` | Set to `true` to verify SSL certificates. The default is intended for trusted self-signed lab environments only. |
| `WAZUH_TIMEOUT` | No | `30` | Request timeout in seconds. Must be a positive integer. |

Alternative variable names `WAZUH_BASE_URL` and `WAZUH_USER` are also supported.

### Wazuh Indexer (OpenSearch) - Required for Alerts

Wazuh 4.x stores alerts in the Wazuh Indexer (OpenSearch), not the REST API. To enable alert tools (`get_alerts`, `get_alert`, `search_alerts`) and the `wazuh://alerts/recent` resource, configure the indexer connection:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
<!-- content-guard: allow private-ipv4 -->
| `WAZUH_INDEXER_URL` | No | - | Wazuh Indexer URL (e.g., `https://10.0.0.2:9200`) |
| `WAZUH_INDEXER_USERNAME` | No | `admin` | Indexer username |
| `WAZUH_INDEXER_PASSWORD` | No | - | Indexer password |
| `WAZUH_INDEXER_VERIFY_SSL` | No | `false` | Set to `true` to verify SSL certificates. The default is intended for trusted self-signed lab environments only. |

If `WAZUH_INDEXER_URL` is not set, alert tools will return a helpful configuration message. All other tools (agents, rules, decoders, version) work without the indexer.

When either SSL verification setting is `false`, the server prints a startup warning to stderr because Node.js applies disabled TLS verification process-wide.

### Sensitive Output Defaults

Several tools return minimized output by default to avoid exposing raw logs, IPs, command lines, hashes, or raw event payloads unless requested:

| Tool | Hidden by default | Opt-in field |
|------|-------------------|--------------|
| `list_agents`, `get_agent`, `get_group_agents` | Agent IP details | `include_ip: true` |
| `get_alerts`, `search_alerts` | `full_log` | `include_full_log: true` |
| `get_alert` | `full_log`, raw `data` | `include_full_log: true`, `include_raw_data: true` |
| `get_agent_processes` | Process command lines and arguments | `include_command: true` |
| `get_fim_files` | MD5 and SHA-256 hashes | `include_hashes: true` |
| `get_manager_logs` | Full log descriptions | `include_description: true` |

## Usage

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "wazuh-mcp",
      "env": {
        "WAZUH_URL": "https://your-wazuh-manager:55000",
        "WAZUH_USERNAME": "wazuh-wui",
        "WAZUH_PASSWORD": "your-password",
        "WAZUH_INDEXER_URL": "https://your-wazuh-indexer:9200",
        "WAZUH_INDEXER_USERNAME": "admin",
        "WAZUH_INDEXER_PASSWORD": "your-indexer-password"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add wazuh \
  --env WAZUH_URL=https://your-wazuh-manager:55000 \
  --env WAZUH_USERNAME=wazuh-wui \
  --env WAZUH_PASSWORD=your-password \
  --env WAZUH_INDEXER_URL=https://your-wazuh-indexer:9200 \
  --env WAZUH_INDEXER_USERNAME=admin \
  --env WAZUH_INDEXER_PASSWORD=your-indexer-password \
  -- wazuh-mcp
```

Add `--scope user` to make it available from any directory instead of only the current project.

### OpenClaw

If you're running from a source checkout instead of the npm-installed binary, point `command`/`args` at the built `dist/index.js`:

```bash
openclaw mcp set wazuh '{
  "command": "node",
  "args": ["/absolute/path/to/wazuh-mcp/dist/index.js"],
  "env": {
    "WAZUH_URL": "https://your-wazuh-manager:55000",
    "WAZUH_USERNAME": "wazuh-wui",
    "WAZUH_PASSWORD": "your-password",
    "WAZUH_INDEXER_URL": "https://your-wazuh-indexer:9200",
    "WAZUH_INDEXER_USERNAME": "admin",
    "WAZUH_INDEXER_PASSWORD": "your-indexer-password"
  }
}'
```

Or, with the global npm install:

```bash
openclaw mcp set wazuh '{
  "command": "wazuh-mcp",
  "env": {
    "WAZUH_URL": "https://your-wazuh-manager:55000",
    "WAZUH_USERNAME": "wazuh-wui",
    "WAZUH_PASSWORD": "your-password",
    "WAZUH_INDEXER_URL": "https://your-wazuh-indexer:9200",
    "WAZUH_INDEXER_USERNAME": "admin",
    "WAZUH_INDEXER_PASSWORD": "your-indexer-password"
  }
}'
```

Then restart the OpenClaw gateway so the new server is picked up:

```bash
systemctl --user restart openclaw-gateway
openclaw mcp list   # confirm "wazuh" is registered
```

### Hermes Agent

[Hermes Agent](https://github.com/NousResearch/hermes-agent) reads MCP config from `~/.hermes/config.yaml` under the `mcp_servers` key. Add an entry:

```yaml
mcp_servers:
  wazuh:
    command: "wazuh-mcp"
    env:
      WAZUH_URL: "https://your-wazuh-manager:55000"
      WAZUH_USERNAME: "wazuh-wui"
      WAZUH_PASSWORD: "your-password"
      WAZUH_INDEXER_URL: "https://your-wazuh-indexer:9200"
      WAZUH_INDEXER_USERNAME: "admin"
      WAZUH_INDEXER_PASSWORD: "your-indexer-password"
```

Or, when running from a source checkout instead of the global npm install:

```yaml
mcp_servers:
  wazuh:
    command: "node"
    args: ["/absolute/path/to/wazuh-mcp/dist/index.js"]
    env:
      WAZUH_URL: "https://your-wazuh-manager:55000"
      WAZUH_USERNAME: "wazuh-wui"
      WAZUH_PASSWORD: "your-password"
      WAZUH_INDEXER_URL: "https://your-wazuh-indexer:9200"
      WAZUH_INDEXER_USERNAME: "admin"
      WAZUH_INDEXER_PASSWORD: "your-indexer-password"
```

Then reload MCP from inside a Hermes session:

```
/reload-mcp
```

### Codex CLI

[Codex CLI](https://github.com/openai/codex) registers MCP servers via `codex mcp add`:

```bash
codex mcp add wazuh \
  --env WAZUH_URL=https://your-wazuh-manager:55000 \
  --env WAZUH_USERNAME=wazuh-wui \
  --env WAZUH_PASSWORD=your-password \
  --env WAZUH_INDEXER_URL=https://your-wazuh-indexer:9200 \
  --env WAZUH_INDEXER_USERNAME=admin \
  --env WAZUH_INDEXER_PASSWORD=your-indexer-password \
  -- wazuh-mcp
```

Or, when running from a source checkout:

```bash
codex mcp add wazuh \
  --env WAZUH_URL=https://your-wazuh-manager:55000 \
  --env WAZUH_USERNAME=wazuh-wui \
  --env WAZUH_PASSWORD=your-password \
  -- node /absolute/path/to/wazuh-mcp/dist/index.js
```

Codex writes the entry to `~/.codex/config.toml` under `[mcp_servers.wazuh]`. Verify with:

```bash
codex mcp list
```

### Standalone

```bash
export WAZUH_URL=https://your-wazuh-manager:55000
export WAZUH_USERNAME=wazuh-wui
export WAZUH_PASSWORD=your-password
npm start
```

### Development

```bash
npm run dev    # Watch mode with tsx
npm run lint   # Type checking
npm test       # Run tests
```

## MCP Tools

### Agent Tools

| Tool | Description |
|------|-------------|
| `list_agents` | List all agents with optional status filtering (active, disconnected, never_connected, pending) |
| `get_agent` | Get detailed info for a specific agent by ID |
| `get_agent_stats` | Get CPU, memory, and disk statistics for an agent |

### Alert Tools

| Tool | Description |
|------|-------------|
| `get_alerts` | Retrieve recent alerts with filtering by level, agent, rule, and text search |
| `get_alert` | Retrieve a single alert by ID |
| `search_alerts` | Full-text search across all alerts |

### Rule Tools

| Tool | Description |
|------|-------------|
| `list_rules` | List detection rules with level and group filtering |
| `get_rule` | Get full rule details including compliance mappings |
| `search_rules` | Search rules by description text |

### SCA Tools (Security Configuration Assessment)

| Tool | Description |
|------|-------------|
| `get_sca_policies` | List SCA policies and scores for an agent (CIS benchmarks, etc.) |
| `get_sca_checks` | Get individual check results with remediation steps and compliance mappings |

### Syscollector Tools (System Inventory)

| Tool | Description |
|------|-------------|
| `get_agent_os` | Get OS information (name, version, architecture, hostname) |
| `get_agent_packages` | List installed software packages with versions |
| `get_agent_processes` | List running processes with PIDs and command lines |
| `get_agent_ports` | List open network ports with associated processes |
| `get_agent_network` | List network interfaces and IP addresses |
| `get_agent_hotfixes` | List installed Windows hotfixes/patches |

### FIM & Rootcheck Tools

| Tool | Description |
|------|-------------|
| `get_fim_files` | Get File Integrity Monitoring results (files, registry keys, hashes) |
| `get_rootcheck` | Get rootkit detection scan findings |

### Manager Tools

| Tool | Description |
|------|-------------|
| `get_manager_logs` | Get Wazuh manager logs filtered by level and module |
| `get_manager_config` | Get active manager configuration by section |

### Group Tools

| Tool | Description |
|------|-------------|
| `list_groups` | List all agent groups |
| `get_group_agents` | List agents in a specific group |

### Other Tools

| Tool | Description |
|------|-------------|
| `list_decoders` | List log decoders with optional name filtering |
| `get_wazuh_version` | Get Wazuh manager version and API info |
| `diagnose_wazuh_connection` | Check sanitized configuration, manager connectivity, and indexer readiness |

## MCP Resources

| Resource URI | Description |
|-------------|-------------|
| `wazuh://agents` | All registered agents and their status |
| `wazuh://alerts/recent` | 25 most recent security alerts |
| `wazuh://rules/summary` | Detection rules sorted by severity |

## MCP Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-alert` | Step-by-step alert investigation with MITRE mapping and remediation |
| `agent-health-check` | Comprehensive agent health assessment (status, resources, alerts) |
| `security-overview` | Full environment security summary with compliance coverage |

## Examples

### List active agents

```
Use list_agents with status "active" to see all connected agents.
```

### Investigate a brute force attempt

```
Search alerts for "brute force" and investigate the top result,
including the MITRE ATT&CK technique and remediation steps.
```

### Check agent health

```
Run an agent health check on agent 001 - check its connection status,
resource usage, and any recent critical alerts.
```

### Find high-severity rules

```
List all rules with level 12 or higher to see critical detection rules
and their compliance framework mappings.
```

## Testing

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
```

Tests use mocked Wazuh API responses - no live Wazuh instance needed.

## Project Structure

```
wazuh-mcp/
├── src/
│   ├── index.ts           # MCP server entry point
│   ├── config.ts          # Environment configuration
│   ├── client.ts          # Wazuh REST API client (JWT auth)
│   ├── indexer-client.ts  # Wazuh Indexer (OpenSearch) client
│   ├── types.ts           # TypeScript type definitions
│   ├── resources.ts       # MCP resource handlers
│   ├── prompts.ts         # MCP prompt templates
│   └── tools/
│       ├── agents.ts      # Agent management tools
│       ├── alerts.ts      # Alert query tools
│       ├── rules.ts       # Rule query tools
│       ├── decoders.ts    # Decoder listing tool
│       ├── version.ts     # Version info tool
│       ├── sca.ts         # Security Configuration Assessment
│       ├── syscollector.ts # System inventory (OS, packages, ports, etc.)
│       ├── syscheck.ts    # File Integrity Monitoring
│       ├── rootcheck.ts   # Rootkit detection
│       ├── manager.ts     # Manager logs and configuration
│       └── groups.ts      # Agent group management
├── tests/
│   ├── client.test.ts     # API client unit tests
│   └── tools.test.ts      # Tool handler unit tests
├── package.json
├── tsconfig.json
├── tsup.config.ts
└── vitest.config.ts
```

## License

MIT
