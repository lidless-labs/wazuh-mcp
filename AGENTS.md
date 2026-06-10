# Repository Guidance

Read-only TypeScript MCP server for the Wazuh SIEM/XDR platform: 28 tools, 3 resources, 3 prompts over stdio. Published to npm as `wazuh-mcp`.

## Definition of Done
```bash
./scripts/verify
```
It runs `npm test`, `npm run typecheck`, and `npm run build` in order, failing fast.

A change is done only when these pass, re-verified after your final edit:
- `npm test` (always)
- `npm run typecheck` (always; alias: `npm run lint`)
- `npm run build` (any change to `src/`, packaging, or the entry point)
- `npm run pack:check` (any change to the publish payload: `dist`, `README.md`, `LICENSE`, `package.json`)

Report actual results. If anything fails, report the failure verbatim and do not claim success.

## Hard Prohibitions
- This server is read-only BY DESIGN. The only POSTs are JWT auth (`/security/user/authenticate`) and indexer `_search`. Before adding ANY state-changing endpoint or tool, stop and get explicit user approval. Do not start with the code.
- Every error returned to an MCP client must pass through `src/safe-error.ts` sanitization. Never return raw API or HTTP errors; they can carry credentials and tokens. New tool? Wrap its error path the same way the existing tools do.
- Tests stay fully mocked. Never hit the live SIEM during development or review unless the user explicitly asks in this session. Need real-shaped data? Extend the mocks in `tests/`.
- Never weaken, skip, or delete a failing test to get green. Fix the code, or report the failure and stop.
- Never push with `--no-verify`. `hooks/pre-push` scans the working tree with content-guard (`~/repos/content-guard`, policy `policies/public-repo.json`). If it blocks: fix the leak, or add an inline `<!-- content-guard: allow <rule-id> -->` tag for a known-safe example (README already carries a few).
- Hit a blocker (missing dep, failing hook, ambiguous requirement)? Report the exact blocker and stop. Do not work around it.

## Project Shape
- `src/index.ts` is the only entry point. It builds `WazuhClient` (manager REST API, JWT auth) and optional `WazuhIndexerClient` (OpenSearch, Basic auth), then calls the per-domain `register*Tools()` functions.
- Tools live one domain per file under `src/tools/` (agents, alerts, rules, decoders, sca, syscollector, rootcheck, syscheck, manager, groups, vulnerabilities, diagnostics, version). Shared input schemas: `src/tools/schemas.ts`. Output shaping: `src/tools/output.ts`. Field redaction: `src/tools/redaction.ts`.
- Config comes from `WAZUH_*` env vars, parsed in `src/config.ts`. Alert and vulnerability tools require `WAZUH_INDEXER_URL`; without it they return a configuration message, not an error. Keep that behavior.

## Verification Commands
- `npm test` runs the vitest suite (`tests/*.test.ts`), all mocked, no live Wazuh needed.
- `npm test -- tests/<specific>.test.ts` for a targeted change.
- `npm run typecheck` is `tsc --noEmit`.
- `npm run build` runs tsup.
- `npm run pack:check` verifies the publish payload (`dist`, `README.md`, `LICENSE`, `package.json` only).
- CI (`.github/workflows/ci.yml`) runs typecheck, build, test, `npm audit --omit=dev`, and pack:check on Node 20 and 22, then publishes to npm on `v*` tags. Match CI locally before declaring done.

## Rules by Trigger
- Touching auth, TLS, or config parsing: keep secure defaults intact. TLS verification stays on by default; sensitive fields (agent IPs, full logs, hashes, command lines) stay hidden unless opted in per call; `get_manager_config` redaction stays enforced server side via `WAZUH_ALLOW_SENSITIVE_CONFIG`.
- Touching a list tool: paginated responses carry both a nested `pagination` object and legacy top-level `total`/`limit`/`offset`. Keep both.
- Touching tool output: responses are size-capped by `WAZUH_MCP_MAX_RESPONSE_BYTES` (default 250000). Oversized output must become a truncated JSON preview with `response_truncated` metadata, never an error.
- Adding alert or vulnerability features: Wazuh 4.x serves those from the indexer, not the manager REST API. Manager-only setups legitimately lack them; preserve the graceful configuration message.
- Adding files in the repo root: `.gitignore` ignores `*.js` and `*.d.ts` everywhere except `tsup.config.ts` and `vitest.config.ts`. Verify new files are actually tracked with `git status`.
- Tempted to run `scripts/proxmox_install.sh`: do not. It provisions an LXC and must run on a Proxmox VE host, never locally.

## Memory Handoff
At the end of any substantial task, write a handoff note to `.claude/memory-handoffs/` using that directory's `TEMPLATE.md`.
Record durable discoveries, gotchas, and decisions. Do not wait to be reminded.
