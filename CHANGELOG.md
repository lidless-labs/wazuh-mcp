# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-10-06

Least-privilege release. The README now sets up read-only Wazuh accounts
instead of `wazuh-wui` and the indexer `admin` user, and `wazuhctrl` works
through npx and global installs. A config that sets `WAZUH_INDEXER_URL`
without `WAZUH_INDEXER_USERNAME` now fails at startup instead of using
`admin`. Like the `WAZUH_INDEXER_PASSWORD` check in 1.1.0, that ships in a
minor version, with the change described under "Upgrading from 2.0.0".

### Upgrading from 2.0.0
- If `WAZUH_INDEXER_URL` is set and `WAZUH_INDEXER_USERNAME` is not, startup
  now fails. Set it to a dedicated indexer user (README: Least-privilege
  setup), or to `admin` to keep the old behavior. Configs copied from the
  2.0.0 README already set it and need no change.

### Fixed
- `wazuhctrl` and `wazuhctl` now run when started through npm's bin symlink,
  which is how npx, global installs, and `node_modules/.bin` start them.
  The entry check compared the symlink path in `process.argv[1]` with the
  module's real path, so the CLI printed nothing and exited 0. The check now
  uses Node's `import.meta.main` where it exists (Node 22.18 and later 22.x
  releases, and 24.2 and later) and otherwise compares both paths after
  `realpathSync`.
- `wazuhctrl mcp` reports a startup error, such as a missing
  `WAZUH_INDEXER_USERNAME`, as the same sanitized JSON error as the other
  commands and exits 1, instead of crashing with an unhandled promise
  rejection and a stack trace.

### Changed
- **Breaking:** when `WAZUH_INDEXER_URL` is set, `WAZUH_INDEXER_USERNAME` is
  required, and a missing or empty value fails at startup with the same kind
  of error as the `WAZUH_INDEXER_PASSWORD` check from 1.1.0. It no longer falls
  back to `admin`. Migration: set `WAZUH_INDEXER_USERNAME` to a dedicated
  indexer user with a read-only role (or to `admin` to keep the old behavior).
- Tools register through the SDK's `registerTool` API instead of the
  deprecated `server.tool`. Tool names, descriptions, and input schemas are
  unchanged.

### Added
- All 28 tools declare the MCP tool annotations `readOnlyHint: true` and
  `openWorldHint: true`, defined once in `src/tools/annotations.ts`. The open
  world hint is true because most tool output originates on monitored
  endpoints and can be written by an attacker, so clients should treat it as
  untrusted content.
  `destructiveHint` and `idempotentHint` are left out because the MCP
  specification gives them meaning only when `readOnlyHint` is false. A test
  lists the tools through an SDK client and fails if any tool lacks them.

### Dependencies
- Lockfile bump of the transitive `proxy-addr` (via the MCP SDK's `express`)
  from 2.0.7 to 2.0.8 for GHSA-jqcg-44mw-7w3h, which failed
  `npm audit --omit=dev`. The stdio server does not run express, and
  `package.json` is unchanged.

### Documentation
- README Quickstart and every client recipe now use a Wazuh API user with the
  built-in `readonly` role and a dedicated indexer user instead of `wazuh-wui`
  and `admin`. On macOS and Linux they load credentials from a 0600 env file
  through a small wrapper script instead of inline passwords in client
  config. The wrapper does not run on Windows, so the README says to run
  `npx -y wazuh-mcp` there with the settings in the client's `env` object or
  `--env` options, and to make that config readable only by your account.
- New README "Least-privilege setup" section: API commands to create the
  `readonly` user, an indexer role with `cluster:monitor/main` plus `read` and
  `indices:admin/get` on `wazuh-alerts-*` and
  `wazuh-states-vulnerabilities-*` with its user and role mapping, and how to
  point `WAZUH_CA_FILE` and `WAZUH_INDEXER_CA_FILE` at the deployment root CA.
  The role pattern matches the concrete vulnerability indices that the
  server's `wazuh-states-vulnerabilities*` queries resolve to. The section
  also notes that default indexer installs map every user to the built-in
  `own_index` role, and that `securityadmin.sh -cd` removes users and roles
  created through the REST API.
- `.env.example` and `CONTRIBUTING.md` follow the same account names and the
  new tool registration helper.

## [2.0.0] - 2026-09-29

Security hardening release. It is a major version because Node.js 20 is no
longer supported and startup now rejects some configurations that 1.x
accepted.

### Upgrading from 1.x
- Run on Node.js 22 or newer.
- Use `https://` for `WAZUH_URL` and `WAZUH_INDEXER_URL`, or set
  `WAZUH_ALLOW_INSECURE_HTTP=true` for a trusted lab network. URLs with
  embedded credentials, a query string, or a fragment are rejected.
- Many endpoint-reported fields now arrive wrapped in `<untrusted_siem_data>`
  markers with `&`, `<`, and `>` entity-escaped. Update anything that
  compares those fields exactly.
- Start the MCP server with the `wazuh-mcp` bin (`dist/mcp-bin.js`), not
  `node dist/index.js`, which is a library entry point since 1.1.4.

### Security
- Escape `&`, `<`, `>` inside `<untrusted_siem_data>` markers so an
  attacker-controlled value containing `</untrusted_siem_data>` cannot close
  the fence early; the untrusted-data note now documents the escaping.
- Cap upstream response bodies (default 16 MiB, per-request overridable) with
  early rejection on oversized `content-length` and byte counting while
  streaming; enforce an absolute wall-clock deadline for headers plus body and
  reject cleanly on response errors/aborts with exactly-once settlement.
- Return a constant `upstream returned invalid JSON` error for unparseable
  upstream bodies instead of leaking a body snippet to the model.
- Redact the bare base64 `user:pass` payload and the full `Basic <payload>`
  header from manager and indexer client errors, not just the username and
  password.
- Route `get_manager_config` output through the shared response-size cap so
  huge configurations truncate with metadata instead of flooding the client.
- Upgrade `@modelcontextprotocol/sdk` to `^1.31.0` and cap the stdio
  read buffer (default 8 MiB, overridable via
  `WAZUH_MCP_MAX_STDIO_BUFFER_BYTES`); oversized client messages make the
  transport error and close.
- Fence endpoint-reported inventory strings in `<untrusted_siem_data>`
  markers with an `output.untrusted_data_note` and a warning in each tool
  description: alert `agent_name`, `location`, and `decoder` in every alert
  tool; agent name and OS fields in `list_agents`, `get_agent`,
  `get_agent_stats`, and `get_group_agents`; all syscollector tools (OS,
  package name/version/architecture/description/vendor, process
  name/euser/cmd/argvs, port process names, interface names, hotfixes); FIM
  paths, `uname`, and `gname`; rootcheck `event`; SCA policy description and
  check description, rationale, remediation, command, and reason; and
  vulnerability package, agent, OS, and description fields. Also agent
  `version`, agent stats `disk`, interface `ipv4`/`ipv6`, SCA policy name and
  check title/condition/references/compliance, and the `wazuh://agents`
  resource. Keys of raw alert `data` are fenced as well, since they come from
  the log.
- `WazuhIndexerClient` rejects `size`/`from` outside the 10000-hit result
  window itself, not only in the MCP tool schemas.
- Validate `WAZUH_URL` and `WAZUH_INDEXER_URL` at startup: reject non-http(s)
  schemes, embedded credentials, query strings, and fragments with a clear
  error.
- Reject plain `http://` service URLs unless `WAZUH_ALLOW_INSECURE_HTTP=true`,
  and print a stderr warning at startup when plaintext is in use.
- Add `WAZUH_CA_FILE` and `WAZUH_INDEXER_CA_FILE` to trust a private CA
  (PEM) instead of disabling verification; unreadable files fail at startup.
- `diagnose_wazuh_connection` reports service URLs as origin only
  (`scheme://host:port`), never path, query, or fragment.

### Changed
- **Breaking:** dropped Node.js 20 (end of life). `engines.node` is now
  `>=22.0.0` and CI tests Node 22 and 24.
- CI supply chain: `actions/checkout` and `actions/setup-node` are pinned to
  commit SHAs, `ci.yml` runs with `permissions: contents: read`, and
  `publish.yml` grants `id-token: write` only to the publish job.
- The publish workflow installs a pinned npm (`11.20.0`, needed for trusted
  publishing) instead of `npm@latest`, and audits with `npm audit --omit=dev`.
- Added `.github/dependabot.yml` with weekly updates for GitHub Actions and
  npm (npm minor and patch updates grouped into one PR).
- Indexer searches send `track_total_hits: 10000` instead of `true` plus a
  `timeout: "30s"`; when the real hit count exceeds 10000, pagination metadata
  (and the `wazuh://alerts/recent` resource) reports
  `total_is_lower_bound: true`.
- Alert and vulnerability tools cap `offset` at 9999 and reject
  `offset + limit > 10000` (OpenSearch's default `max_result_window`) before
  querying. Manager API tools keep the existing offset bound.
- Concurrent manager requests that need a token, or that hit a 401 together,
  now share one in-flight authentication instead of each posting credentials.
- The truncated response envelope now always fits within
  `WAZUH_MCP_MAX_RESPONSE_BYTES` (the preview is sized after subtracting the
  envelope overhead), and caps below 1024 bytes are raised to 1024.
- `.env.example` now defaults to `WAZUH_VERIFY_SSL=true` and
  `WAZUH_INDEXER_VERIFY_SSL=true`, with the `false` opt-outs commented out.

### Removed
- `scripts/proxmox_install.sh`. It targeted an older project, wrote
  `WAZUH_API_KEY` and `PORT` settings this server never reads, and handled
  secrets unsafely.

### Dependencies
- `actions/checkout` 7.0.1 and `actions/setup-node` 7.0.0 (#19, #20), `tsx`
  and `zod` minor updates (#21), vitest 5 (#23), and `@types/node` 26 (#24).
  TypeScript 7 is held back because the tsup declaration build does not
  support it yet (#22).

### Documentation
- OSS adoption upgrade: README now leads with a what/why/how summary, a
  copy-paste `npx -y wazuh-mcp` MCP client config, a "What it does" overview,
  and "Why not the dashboard or raw API?" and "What wazuh-mcp is not"
  sections. Badges and links point at the `lidless-labs/wazuh-mcp` repository.
- Added `SECURITY.md` (threat model and reporting), `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue templates (`bug`, `feature`, routing
  config), and a pull request template with a no-PII checkbox.

## [1.1.4] - 2026-07-06

Released from the `fire/wazuhctrl-2026-07-06` branch; merged back to main on
2026-09-29 so main matches what npm ships.

### Added
- `wazuhctrl` CLI (alias `wazuhctl`) with `status`, `agents list`,
  `diagnostics`, and `mcp` commands. The MCP server keeps the `wazuh-mcp` bin.
- Library entry point (`dist/index.js`) exports the clients, config loader, and
  `createWazuhMcpServer`/`serveMcp`.

### Changed
- npm publishing moved to `.github/workflows/publish.yml` with trusted
  publishing and provenance. 1.1.1 through 1.1.3 were publish-pipeline fixes
  with no runtime changes.

## [1.1.0] - 2026-06-10

Security hardening release. The headline change: **TLS certificate verification
is now ON by default** for both the Wazuh manager and the Wazuh Indexer
connections. The previously published 1.0.0 shipped with verification off by
default; if you rely on a self-signed lab certificate, you must now opt out
explicitly with `WAZUH_VERIFY_SSL=false` and/or `WAZUH_INDEXER_VERIFY_SSL=false`
(the server prints a startup warning when you do).

### Security
- Verify TLS certificates by default for the manager and indexer clients;
  disabling verification is now an explicit opt-out that logs a startup
  warning (`security: verify TLS by default`).
- Gate unredacted `get_manager_config` output behind the server-side
  `WAZUH_ALLOW_SENSITIVE_CONFIG` flag; a model-supplied tool argument can
  never enable it on its own.
- Delimit attacker-influenced SIEM content returned to the model: alert
  `full_log`, alert `rule_description`, raw event `data`, and manager log
  descriptions are wrapped in `<untrusted_siem_data>` markers with an
  `output.untrusted_data_note` warning, and the affected tool descriptions
  flag the fields as data, never instructions.
- Route all tool-level error returns through the `safe-error` sanitizer so
  errors that bypass the client wrappers (JSON parse errors with body
  snippets, URL errors) never reach the MCP client raw.
- Fail fast at startup when `WAZUH_INDEXER_URL` is set without
  `WAZUH_INDEXER_PASSWORD` instead of silently sending an empty password.
- Minimize sensitive tool output by default: agent IPs, alert full logs, raw
  event data, process command lines, file hashes, and manager log
  descriptions are hidden unless opted in per call.
- Validate all MCP tool inputs with strict schemas: bounded pagination,
  length-limited search text, per-tool sort enums, and allowlisted
  identifiers for agent, alert, group, and SCA policy IDs.
- Encode Wazuh API path segments to prevent path injection.
- General security hardening pass across clients and tools, including
  sanitized diagnostics output that redacts URLs and never returns
  credentials.

### Added
- Indexer-backed vulnerability tools: `list_vulnerabilities` and
  `search_vulnerabilities`.
- Response size caps via `WAZUH_MCP_MAX_RESPONSE_BYTES` (default 250000);
  oversized responses return a truncated JSON preview with
  `output.response_truncated` metadata instead of an error.
- `pagination` object (`total`, `limit`, `offset`, `has_more`) on paginated
  tool responses, alongside the existing top-level fields.
- Transient-error retries for manager `GET` and indexer search requests on
  `429`, `502`, `503`, `504`, and common network reset or timeout errors.
- `AGENTS.md` contributor guide and a `scripts/verify` entrypoint that runs
  test, typecheck, and build in order.

### Changed
- The MCP server version reported in handshakes is now derived from
  `package.json` instead of a hardcoded constant.
- Documentation and test fixtures use RFC 5737 documentation addresses
  (`192.0.2.x`) instead of RFC 1918 space.
- Dependencies refreshed; `npm audit` clean.

### Fixed
- Strip the draft-07 `$schema` marker the MCP SDK stamps on tool schemas,
  which some clients reject when listing the full tool set.

### CI
- Publish with npm provenance (`npm publish --provenance` with
  `id-token: write`).
- Skip npm publish when the version already exists on the registry, making
  tag builds idempotent.

## [1.0.0] - 2026-04-29

Initial release: read-only MCP server for the Wazuh SIEM/XDR platform with
28 tools, 3 resources, and 3 prompts over stdio. Covers agents, alerts,
rules, decoders, SCA, syscollector, rootcheck, FIM, manager logs and
configuration, groups, and connection diagnostics, with optional Wazuh
Indexer (OpenSearch) support for alert queries.

[Unreleased]: https://github.com/lidless-labs/wazuh-mcp/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/lidless-labs/wazuh-mcp/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/lidless-labs/wazuh-mcp/compare/v1.1.4...v2.0.0
[1.1.4]: https://github.com/lidless-labs/wazuh-mcp/compare/v1.1.0...v1.1.4
[1.1.0]: https://github.com/lidless-labs/wazuh-mcp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lidless-labs/wazuh-mcp/releases/tag/v1.0.0
