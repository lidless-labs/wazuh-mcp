# line-check report: wazuh-mcp (2026-06-10)

## Verdict
wazuh-mcp is in strong shape: clean domain-per-file structure, 94 green mocked tests on Node 20 and 22, accurate README and AGENTS.md, zero TODO debt, zero open issues, and tight hygiene (agent dirs ignored, no secrets in history, only 2 runtime deps with 0 audit findings). The one station that drags is release hygiene: the npm package is frozen at v1.0.0 from April 29, which still ships TLS verification OFF by default, while main carries 21 commits of security hardening (TLS verify by default, input validation, output minimization, transport hardening) that nobody installing from npm gets. The single most important thing to do is cut a release. Overall: healthy, with one high-leverage gap.

## Scorecard
| Station | Score (0-5) | Summary |
|---|---|---|
| 1. Docs and onboarding | 5 | README is thorough and accurate; "28 MCP Tools" claim verified against registerTool counts; quickstart and dev commands match package.json; config examples for 5 clients |
| 2. Agent-readiness | 5 | AGENTS.md is current and specific (verify entrypoint, hard prohibitions, rules by trigger); `brigade handoff doctor` all-ok (10 processed handoffs); `brigade memory care scan` clean (0 cards, 0 issues) |
| 3. Tests and CI | 4 | 94 tests pass locally in 315ms; CI green on Node 20+22 with typecheck, build, test, audit, pack:check; gap: `src/resources.ts` and `src/prompts.ts` have zero test coverage |
| 4. Hygiene | 5 | .gitignore covers `.claude/`, `.codex/`, `.brigade/`, `/memory/`, env files, build artifacts; MIT LICENSE present; `.env` never committed and history grep for the credential is clean; no stale branches (main only) |
| 5. Structure | 5 | Largest file is 438 lines (`indexer-client.ts`); one domain per tool file; shared schemas/output/redaction modules; 2 runtime deps, all current, `npm audit --omit=dev` clean |
| 6. Release hygiene | 2 | No CHANGELOG; v1.0.0 tag is 21 commits and 6 weeks behind main; published npm 1.0.0 lacks the security fixes; server version hardcoded as "1.0.0" in `src/index.ts:45` |
| 7. TODO and issue mining | 5 | Zero TODO/FIXME/HACK markers in src, tests, scripts, hooks; zero open issues and PRs |

## Findings

### [HIGH] Cut a release: published npm package still ships TLS verification off by default
- **Station:** Release hygiene
- **Where:** v1.0.0 tag vs main; `git show v1.0.0:src/config.ts` line 39 (`?? "false"`) vs current `src/config.ts:58` (`parseBooleanEnv(..., true)`)
- **What:** npm has wazuh-mcp@1.0.0 (verified via `npm view`), built from the April 29 tag where `WAZUH_VERIFY_SSL` and `WAZUH_INDEXER_VERIFY_SSL` default to `false`. Main fixed that on 2026-06-08 (commit 20b286c) and also added input validation, output minimization, sensitive-config gating, and transport hardening, none of which is published.
- **Why it matters:** Everyone installing from npm runs a SIEM client that skips certificate verification by default, exposing Wazuh API credentials and JWTs to MITM. The README on GitHub documents the new secure behavior, so the published package silently contradicts its own docs.
- **Fix:** Bump `package.json` version (the flipped TLS default is a behavior change, so 2.0.0 is the honest pick), update the hardcoded version in `src/index.ts:45`, run `npm run pack:check`, then `git tag v2.0.0 && git push --tags`. CI's publish job handles npm with its already-published guard.
- **Effort:** S

### [MEDIUM] Add a CHANGELOG
- **Station:** Release hygiene
- **Where:** repo root (file absent)
- **What:** No CHANGELOG.md exists. The 21 commits since v1.0.0 include user-facing behavior changes (TLS default flip, new pagination object, response size caps, new env vars) that are only discoverable by reading git log.
- **Why it matters:** The TLS default flip in particular will break setups relying on the old insecure default; without a changelog there is nowhere to warn them at upgrade time.
- **Fix:** Create CHANGELOG.md in Keep a Changelog format, backfill from `git log v1.0.0..main` (the conventional-commit subjects map cleanly), and cut the entries as part of the release above. Add "update CHANGELOG" to the release checklist in AGENTS.md.
- **Effort:** S

### [MEDIUM] Resources and prompts have zero test coverage
- **Station:** Tests and CI
- **Where:** `src/resources.ts` (115 lines), `src/prompts.ts` (88 lines); no file in `tests/` references either
- **What:** All 6 test files target the clients, tools, config, schemas, and output shaping. The 3 MCP resources (`wazuh://agents`, `wazuh://alerts/recent`, `wazuh://rules/summary`) and 3 prompts are exercised nowhere.
- **Why it matters:** The alerts/recent resource depends on the indexer-optional code path that AGENTS.md explicitly says must keep returning a configuration message instead of an error; a regression there ships untested today.
- **Fix:** Add `tests/resources.test.ts` and `tests/prompts.test.ts` using the same mocked-client pattern as `tests/tools.test.ts`; cover the indexer-unconfigured path for `wazuh://alerts/recent` specifically.
- **Effort:** M

### [LOW] Derive the MCP server version from package.json
- **Station:** Release hygiene
- **Where:** `src/index.ts:45` (`version: "1.0.0"`)
- **What:** The version string handed to the MCP SDK is hardcoded and already represents stale information relative to main's content.
- **Why it matters:** Every release bump now requires editing two files; the first forgotten bump means clients see the wrong server version in handshakes and bug reports.
- **Fix:** Import it: `import pkg from "../package.json" with { type: "json" }` (tsconfig already targets a modern module mode; verify `resolveJsonModule`/import-attributes support, otherwise have tsup define it at build time). Then `version: pkg.version`.
- **Effort:** S

### [INFO] Real lab credentials sit in the untracked working-tree .env
- **Station:** Hygiene
- **Where:** `/home/clawdbot/repos/wazuh-mcp/.env`
- **What:** The local `.env` holds a live lab Wazuh URL and password. It is gitignored, was never committed, and a credential grep across all history is clean, so this is local exposure only.
- **Why it matters:** Any future `.gitignore` refactor or a tool that bundles the working tree (tarballs, AI context dumps) could leak it. The pre-push content-guard hook is the existing backstop.
- **Fix:** Nothing required for the repo. Optionally move the credential to the workspace-level env store and keep `.env` pointing at a non-production account.
- **Effort:** S

### [INFO] Publish job has no npm provenance
- **Station:** Release hygiene
- **Where:** `.github/workflows/ci.yml` publish job
- **What:** Publishing uses a long-lived `NPM_TOKEN` secret with `permissions: contents: read` and no `id-token: write`, so packages carry no provenance attestation.
- **Why it matters:** For a security tool, provenance is cheap trust signal; a leaked classic token can also publish from anywhere.
- **Fix:** Add `id-token: write` to the publish job's permissions and change the publish line to `npm publish --provenance`, or move to npm Trusted Publishing and drop the token entirely.
- **Effort:** S

### [INFO] Lint is typecheck-only, by design
- **Station:** Tests and CI
- **Where:** `package.json` scripts (`"lint": "tsc --noEmit"`)
- **What:** There is no ESLint or Prettier; AGENTS.md documents `lint` as an alias for typecheck. Recorded as a deliberate choice, not a finding.
- **Why it matters:** Awareness only. The codebase is small and consistent; tsc strict mode carries most of the weight.
- **Fix:** None required.
- **Effort:** S

## Backlog
1. [HIGH/S] Cut a release so npm gets TLS-verify-by-default and the hardening sweep (Release hygiene)
2. [LOW/S] Derive the MCP server version from package.json (Release hygiene)
3. [MEDIUM/S] Add a CHANGELOG and backfill from v1.0.0..main (Release hygiene)
4. [INFO/S] Add npm provenance to the publish job (Release hygiene)
5. [MEDIUM/M] Add tests for resources.ts and prompts.ts, covering the indexer-unconfigured path (Tests and CI)
6. [INFO/S] Move the live lab credential out of the local .env (Hygiene)

## Not checked
- Live Wazuh behavior: tests are fully mocked by design and AGENTS.md prohibits hitting the live SIEM; no tool calls were made against the manager or indexer.
- `node_modules/` and `dist/`: generated trees, excluded per skill rules.
- `scripts/proxmox_install.sh` functional correctness: it must run on a Proxmox VE host (AGENTS.md forbids running it locally); it was only scanned for embedded secrets (clean, CT password is openssl-generated).
- `docs/assets/wazuh-mcp-banner.jpg`: binary asset, not inspected beyond existence.
- npm package tarball contents of the published 1.0.0: only the version and the tagged source were compared, not the literal published artifact.
