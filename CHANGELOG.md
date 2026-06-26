# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation
- OSS adoption upgrade: README now leads with a what/why/how summary, a
  copy-paste `npx -y wazuh-mcp` MCP client config, a "What it does" overview,
  and "Why not the dashboard or raw API?" and "What wazuh-mcp is not"
  sections. Badges and links point at the `lidless-labs/wazuh-mcp` repository.
- Added `SECURITY.md` (threat model and reporting), `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue templates (`bug`, `feature`, routing
  config), and a pull request template with a no-PII checkbox.

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

[1.1.0]: https://github.com/solomonneas/wazuh-mcp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/solomonneas/wazuh-mcp/releases/tag/v1.0.0
