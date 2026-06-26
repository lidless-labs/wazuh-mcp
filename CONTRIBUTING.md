# Contributing to wazuh-mcp

wazuh-mcp is a read-only [Model Context Protocol](https://modelcontextprotocol.io/) server for the [Wazuh](https://wazuh.com/) SIEM/XDR platform. Patches are welcome. Before you start, please skim this file so we both spend our time on the right things.

## What kinds of changes land easily

- **Bug fixes** in tool handlers, the Wazuh REST client, the indexer client, config parsing, output shaping, or redaction.
- **Better tool descriptions and schemas** that help a model call the right tool with the right arguments.
- **New read-only tools** that map cleanly onto an existing Wazuh manager or indexer endpoint.
- **Sharper error messages and diagnostics**, as long as they stay sanitized (no credentials, no raw API bodies).
- **Test coverage** for any of the above, using the existing mocked fixtures.
- **Docs**: README clarifications, configuration examples, client recipes.

## What needs a conversation first

- **Any state-changing endpoint or tool.** This server is read-only by design. The only writes are JWT authentication against the manager and `_search` against the indexer. Adding anything that mutates Wazuh state (restart an agent, edit a rule, acknowledge an alert) requires an issue and explicit maintainer sign-off before you write code. Do not start with the code.
- **Changes to redaction or TLS defaults.** Sensitive fields stay hidden unless opted in per call; TLS verification stays on by default; `get_manager_config` stays gated behind `WAZUH_ALLOW_SENSITIVE_CONFIG`. Loosening any of these needs a discussion.
- **New runtime dependencies.** The server runs on `@modelcontextprotocol/sdk` and `zod` only. Adding a third needs a strong reason.
- **Breaking changes** to tool names, response shapes, or environment variable names.

## What does not land

- Personal details, hostnames, real IPs, account IDs, or live credentials in code, docs, or tests. Documentation and fixtures use RFC 5737 addresses (`192.0.2.x`) and generic names. The `content-guard` pre-push hook and the CI guard will flag any of this.
- Tools or error paths that return raw Wazuh API or HTTP errors. Every error returned to the client must go through `src/safe-error.ts`.
- Tests that hit a live Wazuh instance. The suite is fully mocked; extend the mocks in `tests/` instead.
- Weakening, skipping, or deleting a failing test to get green.
- AI co-authorship trailers on commits (`Co-Authored-By: <model>`). Conventional commits only.

## Definition of done

A change is done only when the project's verify script passes, re-run after your final edit:

```bash
./scripts/verify   # runs npm test, npm run typecheck, npm run build in order
```

For changes to the publish payload (`dist`, `README.md`, `LICENSE`, `package.json`), also run:

```bash
npm run pack:check
```

CI (`.github/workflows/ci.yml`) runs typecheck, build, test, `npm audit --omit=dev`, and pack:check on Node 20 and 22. Match it locally before declaring done. Report actual results; if anything fails, report the failure verbatim and do not claim success.

## Local dev

```bash
git clone https://github.com/lidless-labs/wazuh-mcp.git
cd wazuh-mcp
npm install
npm run build
npm test
```

`npm run dev` runs the server in watch mode with `tsx`. You do not need a live Wazuh instance for development; the test suite is fully mocked. To smoke-test against a real Wazuh manager, set the `WAZUH_*` environment variables (see the README) and run `npm start`.

## Project shape

- `src/index.ts` is the only entry point. It builds the `WazuhClient` (manager REST API, JWT auth) and the optional `WazuhIndexerClient` (OpenSearch, basic auth), then calls the per-domain `register*Tools()` functions.
- Tools live one domain per file under `src/tools/` (agents, alerts, rules, decoders, sca, syscollector, rootcheck, syscheck, manager, groups, vulnerabilities, diagnostics, version). Shared input schemas live in `src/tools/schemas.ts`, output shaping in `src/tools/output.ts`, and field redaction in `src/tools/redaction.ts`.
- Config comes from `WAZUH_*` env vars, parsed in `src/config.ts`. Alert and vulnerability tools require `WAZUH_INDEXER_URL`; without it they return a configuration message, not an error. Keep that behavior.

## Adding a tool

1. Add the handler to the matching domain file under `src/tools/` (or a new file if it is a new domain), registering it with `server.tool(...)`.
2. Define its input schema with Zod. Reuse the shared schemas in `src/tools/schemas.ts` for pagination and identifiers.
3. Route every error path through `src/safe-error.ts`. Never return a raw API or HTTP error.
4. If the tool returns attacker-influenced SIEM text, delimit it with `<untrusted_siem_data>` markers the way the existing alert and manager tools do.
5. Add it to the tool table in `README.md`.
6. Add a test in `tests/` against mocked fixtures.

## Filing issues

Please use the templates under `.github/ISSUE_TEMPLATE/`. For bugs, include the wazuh-mcp version, your Node version, your OS, and the full sanitized output. Before posting, remove tokens, private hostnames, real IPs, and unredacted absolute paths.

## License

By contributing you agree that your contribution is licensed under the MIT License, same as the rest of the repo.
