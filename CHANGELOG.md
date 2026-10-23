# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- JMAP core: autodiscovery from an email address (DNS SRV `_jmap._tcp`, then
  `/.well-known/jmap`), session handling tolerant of unknown capabilities,
  blob upload and download, JMAP error model.
- SSRF guard for every outbound request: HTTPS only, no private, loopback or
  link-local destinations, checked at connection time, limited redirects.
- Compact email representation: summaries, full messages with HTML converted
  to text and bodies truncated with an explicit flag.
- Read tools over stdio: `list_accounts`, `list_mailboxes`, `search_emails`,
  `get_email`, `get_thread`, `get_attachment`, and the `jmap-mcp://status`
  resource.
- Local OAuth for the stdio mode: the process discovers the mail server's
  authorization server (RFC 9728, RFC 8414, OpenID discovery), registers
  itself as a public client (RFC 7591), signs in through the browser with a
  loopback redirect and PKCE, or through the device flow (RFC 8628) when no
  browser can be opened. Tokens are refreshed transparently.
- `connect_account` tool; the email address is asked by elicitation when the
  client supports it. Several accounts can be connected; when no default is
  set, the account is asked once and remembered.
- Write tools: `update_emails` (read, flagged), `move_emails` (by id, role or
  name), `delete_emails` (trash by default, permanent destruction only after
  confirmation), `create_draft` (replies with In-Reply-To, References, quote
  and reply-all recipients, attachments uploaded to the server) and
  `send_email` (disabled unless `--enable-send`; every message is confirmed by
  the user through elicitation, or by an explicit `confirm` argument when the
  client cannot ask).
- Optional tools registered only when the server announces the capability:
  `list_identities` and `send_email` (submission), `vacation_response`,
  `sieve_scripts` (RFC 9661, changes confirmed by the user).
- Elicitation works with clients on the 2026-07-28 protocol (multi round-trip
  requests) and with older clients (direct `elicitation/create`).
- Encrypted SQLite store (AES-GCM, master key generated on first start and
  kept in the OS keyring when available, otherwise in a 0600 file).
- Integration tests against Stalwart in Docker, and unit tests replaying the
  recorded JMAP exchanges.
