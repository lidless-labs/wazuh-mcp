<!--
Thanks for sending a patch. Keep this short; delete sections that do not apply.
See CONTRIBUTING.md for what lands easily and what needs an issue first.
-->

## What and why

<!-- One or two sentences on the user-visible change and the problem it solves. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New read-only tool / schema improvement
- [ ] Docs
- [ ] Refactor with no behavior change
- [ ] State-changing tool or endpoint (opened an issue first and got maintainer sign-off per CONTRIBUTING.md)

## Checklist

- [ ] `./scripts/verify` passes locally (`npm test`, `npm run typecheck`, `npm run build`)
- [ ] `npm run pack:check` run if the publish payload changed (`dist`, `README.md`, `LICENSE`, `package.json`)
- [ ] Added or updated tests against mocked fixtures; no test hits a live Wazuh instance
- [ ] Every new error path is routed through `src/safe-error.ts` (no raw API or HTTP errors reach the client)
- [ ] Redaction and TLS defaults are intact (sensitive fields opt-in only, TLS verification on by default)
- [ ] Updated the `Unreleased` section of `CHANGELOG.md` for any user-visible effect
- [ ] No personal data, real hostnames, real IPs, account names, tokens, or unredacted absolute paths in code, docs, tests, or this PR description (docs and fixtures use `192.0.2.x` / generic names; the content-guard hook will fail otherwise)
- [ ] Conventional commit messages, no AI co-authorship trailers
