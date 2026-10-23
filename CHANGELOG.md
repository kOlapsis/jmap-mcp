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
- Integration tests against Stalwart in Docker, and unit tests replaying the
  recorded JMAP exchanges.
