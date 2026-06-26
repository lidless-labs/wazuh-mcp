# Security Policy

## Supported versions

wazuh-mcp follows semantic versioning. Only the latest released minor on the `main` branch receives security fixes. Pin to a published tag if you need a known-good version.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Email **me@solomonneas.dev** with: <!-- content-guard: allow pii/email -->

- A short description of the issue.
- Steps to reproduce (or a minimal proof of concept).
- The version or commit you tested against.
- Whether you would like to be credited in the release notes.

You should get an acknowledgment within 72 hours. If you do not, please follow up - the mail may have been filtered.

## Threat model

wazuh-mcp is a read-only MCP server that an AI client uses to query a Wazuh SIEM/XDR deployment. Two trust boundaries matter:

1. **Server to Wazuh.** The server holds your Wazuh manager and indexer credentials and talks to them over TLS. Credentials must never leak back to the MCP client.
2. **Wazuh to the model.** Alert and log fields originate on monitored endpoints. Anyone who can write a log line on a monitored host controls the text that lands in `full_log`, alert `rule_description`, raw event `data`, and manager log descriptions. That text is attacker-influenced and must not be treated as instructions to the model.

## In scope

- **Credential or token leaks** in tool responses, error messages, or diagnostics. Every error returned to the client must pass through `src/safe-error.ts`; a path that returns a raw Wazuh API or HTTP error (which can carry a JWT or basic-auth header) is a vulnerability.
- **Redaction bypasses.** Cases where agent IPs, alert `full_log`, raw event `data`, process command lines, file hashes, or secret-like manager config reach the client without the documented opt-in, or where `get_manager_config` returns sensitive values while `WAZUH_ALLOW_SENSITIVE_CONFIG` is unset/`false`.
- **Prompt-injection delimiting failures.** Untrusted SIEM content that reaches the model without the `<untrusted_siem_data>` markers and `output.untrusted_data_note` warning.
- **TLS downgrade.** Cases where certificate verification is silently disabled when neither `WAZUH_VERIFY_SSL` nor `WAZUH_INDEXER_VERIFY_SSL` is set to a false value.
- **Input validation bypass.** Path injection through agent, alert, group, or SCA policy identifiers, or unbounded pagination/search input reaching Wazuh.
- **Read-only violations.** Any tool that issues a state-changing request to Wazuh beyond JWT authentication and indexer `_search`.

## Out of scope

- Bugs in Wazuh itself (manager, indexer, agents). Report those to the [Wazuh project](https://github.com/wazuh/wazuh).
- Bugs in `content-guard`, the MCP SDK, or your MCP client. Report those to their respective projects.
- Issues that require an attacker to already have read access to your MCP client config or the machine running the server (where the credentials live).
- A Wazuh account you configured with broader privileges than intended. The server uses the credentials you give it and can see only what that account can see.
- Disabling TLS verification yourself with `WAZUH_VERIFY_SSL=false` for a lab certificate. The server warns you when you do; the risk is then yours.

## Disclosure

We aim to ship a fix within 14 days of confirming a valid report. A coordinated disclosure timeline can be negotiated for issues that need longer.
