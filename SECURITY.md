# Security policy

jmap-mcp handles access to people's mailboxes, so security reports are taken seriously.

## Reporting a vulnerability

Please do not open a public issue. Report it privately, either:

- through GitHub: **Security › Report a vulnerability** on
  [kOlapsis/jmap-mcp](https://github.com/kOlapsis/jmap-mcp/security/advisories/new), or
- by email to **security@kolapsis.com**.

Include the affected version, a description of the issue, its impact and the steps to reproduce.
You will get an acknowledgment within three working days. We will keep you informed while we fix
it and credit you in the advisory unless you prefer otherwise.

## Supported versions

Security fixes go into the latest minor release. Upgrade to the latest version before reporting.

## Scope

In scope: the bridge itself (OAuth endpoints, token handling, the SSRF guard, the MCP tools, the
HTML pages, the container image). Vulnerabilities of mail servers or MCP clients should be reported
to their own projects; tell us if they affect jmap-mcp users.
