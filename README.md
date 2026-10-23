# jmap-mcp

[![CI](https://github.com/kOlapsis/jmap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/kOlapsis/jmap-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/kOlapsis/jmap-mcp)](https://github.com/kOlapsis/jmap-mcp/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/kOlapsis/jmap-mcp.svg)](https://pkg.go.dev/github.com/kOlapsis/jmap-mcp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

An MCP server that gives an AI assistant (Claude.ai, Claude Code, Claude Desktop or any MCP client)
access to a mailbox hosted on a JMAP server ([RFC 8620](https://www.rfc-editor.org/rfc/rfc8620),
[RFC 8621](https://www.rfc-editor.org/rfc/rfc8621)), first of all [Stalwart](https://stalw.art).

The user gives an email address and signs in on their mail server's own page. Nothing else is
configured: no server URL, no token, no API key.

## Why

- **Sovereignty.** Your mail stays on your server. The bridge is self-hosted, stores no email, and
  keeps only encrypted OAuth tokens.
- **Zero configuration.** The JMAP server is found from the email address (DNS SRV, then
  `/.well-known/jmap`), its OAuth server from standard metadata, and the bridge registers itself
  dynamically. Secrets are generated on first start.
- **Clean OAuth, no token passthrough.** MCP clients get tokens issued by the bridge for the bridge;
  mail-server tokens never leave it, as the
  [MCP authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) requires.
  It works as a Claude.ai custom connector with the Client ID left empty.
- **Any JMAP server.** Nothing is Stalwart-specific: any server with JMAP and an OAuth server
  supporting RFC 8414 metadata and RFC 7591 dynamic registration works.

Existing JMAP MCP servers ([mikluko/jmap-mcp](https://github.com/mikluko/jmap-mcp),
[wyattjoh/jmap-mcp](https://glama.ai/mcp/servers/@wyattjoh/jmap-mcp),
[agent-jmap-mcp](https://pypi.org/project/agent-jmap-mcp/),
[fastmail-blade-mcp](https://pypi.org/project/fastmail-blade-mcp/)) all need a server URL and a
static token in their configuration, and none can be added to Claude.ai as a connector.

## Tools

A small surface designed for an agent: compact JSON results, pagination everywhere, bodies
converted to text and truncated with an explicit flag.

| Tool | What it does |
|---|---|
| `list_accounts` | Connected accounts and the default one (`set_default` changes it). |
| `connect_account` | Local mode only: connect an account from an email address (browser or device code). |
| `list_mailboxes` | Mailboxes with role (inbox, sent, drafts, trash, archive, junk), path, total and unread counts. |
| `list_identities` | Sender identities. Registered when the server announces submission. |
| `search_emails` | Text, sender, recipient, subject, mailbox, dates, unread, flagged, attachments, size; sort; position and limit. Returns summaries. |
| `get_email` | Headers, plain-text body (HTML converted when there is no text part), attachment list. `max_body_length`. |
| `get_thread` | A conversation in order, as summaries or full messages. |
| `get_attachment` | Text and small images inline; otherwise a signed URL valid 15 minutes (HTTP mode) or a private temporary file (local mode). |
| `update_emails` | Read, unread, flagged, unflagged. |
| `move_emails` | Move to a mailbox given by id, role or name. |
| `delete_emails` | Trash by default; `permanent` destroys after the user's confirmation. |
| `create_draft` | New message or reply: In-Reply-To, References, `Re:` subject, quote, reply-all recipients, attachments uploaded over JMAP. |
| `send_email` | Sends a draft, or composes and sends. Disabled unless `--enable-send`; every message is confirmed by the user. |
| `vacation_response` | Read or change the out-of-office reply (changes are confirmed). Registered when the server announces it. |
| `sieve_scripts` | List, read, write, activate, deactivate, delete filtering rules ([RFC 9661](https://www.rfc-editor.org/rfc/rfc9661)); changes are confirmed. Registered when announced. |

The resource `jmap-mcp://status` describes the connected accounts, the discovered servers and the
capabilities they announce.

Email content is treated as untrusted data: it is returned to the model as data, never interpreted,
and the tool descriptions tell the model that emails may contain instructions it must ignore.

Choices that are not secret (which account, which sender identity, confirmation of a send or a
permanent deletion) are asked through MCP elicitation when the client supports it. Otherwise the
tool returns an error listing the choices, and the model calls it again with the argument set
(`account`, `identity`, `confirm`). Credentials never go through elicitation or tool arguments.

## How it works

```
                         HTTP mode                                     mail server
 ┌──────────────┐  OAuth 2.1 (bridge tokens)  ┌──────────────┐  OAuth (mail tokens)  ┌──────────────┐
 │  MCP client  │ ──────────────────────────▶ │   jmap-mcp   │ ────────────────────▶ │ OAuth server │
 │  Claude.ai…  │ ◀── MCP over HTTP ────────▶ │  (bridge)    │ ◀──── JMAP ─────────▶ │  JMAP API    │
 └──────────────┘                             └──────────────┘                       └──────────────┘
```

In **HTTP mode** (`jmap-mcp serve`) the bridge is at the same time:

1. a protected resource ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) metadata, `401` with
   `WWW-Authenticate`, audience checked on every request);
2. a minimal authorization server for MCP clients ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)
   metadata, PKCE S256, [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators,
   [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) dynamic registration, Client ID Metadata
   Documents, rotating refresh tokens);
3. an OAuth client of the mail server: its sign-in page asks for the email address, discovers the
   server, registers itself there once per server, and redirects the user to the mail server's
   authorization code flow with PKCE. Only after the mail server returns does the bridge issue its
   own code and tokens.

A single deployment serves users of different mail servers. Each user gets an isolated MCP server
instance and can only reach their own accounts.

In **local mode** (`jmap-mcp`, stdio) there is no third party: the process is the OAuth client of
the mail server, like a mail application. It registers as a public client, opens the browser on a
loopback redirect, and falls back to the device flow ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628))
when no browser can be opened, showing the code to type.

## Installation

### 1. Docker behind Traefik

The image is `ghcr.io/kolapsis/jmap-mcp` (linux/amd64 and linux/arm64, distroless, non-root, data
in the `/data` volume). With a Traefik that already has a `websecure` entrypoint and an ACME
resolver, copy [`docker-compose.yml`](docker-compose.yml), set your host name, resolver and network,
and start it:

```sh
curl -O https://raw.githubusercontent.com/kOlapsis/jmap-mcp/main/docker-compose.yml
# edit mcp.example.com, the certresolver name and the network
docker compose up -d
curl https://mcp.example.com/healthz
```

Traefik sets the `X-Forwarded-*` headers from which the bridge derives its public URL. Set
`JMAP_MCP_PUBLIC_URL` only if your proxy does not send them.

Image tags: `X.Y.Z`, `X.Y`, `X` and `latest` for releases, `main` and `sha-<commit>` for the
latest build of the main branch. Both are built by GitHub Actions and pushed to ghcr.io.

**Without Traefik**, [`deploy/caddy`](deploy/caddy) has a Caddy setup that obtains the certificate
itself:

```sh
cd deploy/caddy   # edit mcp.example.com in the Caddyfile
docker compose up -d
```

The MCP address is `https://mcp.example.com/mcp`.

### 2. Add it to Claude.ai

Settings › Connectors › **Add custom connector**. Give it a name and the URL
`https://mcp.example.com/mcp`. Leave **Client ID** and **Client Secret** empty in the advanced
settings: Claude.ai registers itself dynamically (its redirect URI is
`https://claude.ai/api/mcp/auth_callback`). Click Connect, enter your email address on the bridge
page, then sign in on your mail server.

The free plan is limited to one custom connector. On Team and Enterprise plans, an owner adds the
connector under Organization settings › Connectors.

### 3. Claude Code with the remote bridge

```sh
claude mcp add --transport http mail https://mcp.example.com/mcp
```

Then run `/mcp` in Claude Code and choose the server to authenticate in the browser.

### 4. Claude Code and Claude Desktop, local (stdio)

Install the binary, from the [releases](https://github.com/kOlapsis/jmap-mcp/releases), with
Homebrew (`brew install --cask kolapsis/tap/jmap-mcp`, macOS and Linux) or with Go:

```sh
go install github.com/kOlapsis/jmap-mcp@latest
```

Claude Code:

```sh
claude mcp add mail -- jmap-mcp
```

or in `.mcp.json`:

```json
{
  "mcpServers": {
    "mail": { "command": "jmap-mcp", "args": ["stdio"] }
  }
}
```

Claude Desktop: install `jmap-mcp.mcpb` from the release (double-click it, or Settings ›
Extensions), or add to `claude_desktop_config.json` the full path of the binary:

```json
{
  "mcpServers": {
    "mail": { "command": "/usr/local/bin/jmap-mcp", "args": ["stdio"] }
  }
}
```

On first use, ask the assistant to connect your mailbox. It asks for your email address
(elicitation, or the `connect_account` tool), opens your browser on the mail server's sign-in page,
and the account is ready. Without a graphical session (SSH), it shows a URL and a code to enter on
any device. Tokens are stored in the data directory (`~/.config/jmap-mcp` on Linux), encrypted with
a key kept in the OS keyring, or in a `0600` key file when no keyring is available. Several accounts
can be connected.

To send email in local mode, add `"env": {"JMAP_MCP_ENABLE_SEND": "true"}` to the server entry.

### 5. Binary with systemd

```sh
sudo install -m 755 jmap-mcp /usr/local/bin/
sudo cp deploy/systemd/jmap-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now jmap-mcp
```

The unit listens on `127.0.0.1:8080` with a dynamic user and its state in `/var/lib/jmap-mcp`. Put
a TLS reverse proxy in front of it (any proxy that sends `X-Forwarded-Proto` and
`X-Forwarded-Host`), or set `JMAP_MCP_PUBLIC_URL`.

## Preparing the mail server

**Discovery.** The JMAP server is found from the email domain, as RFC 8620 §2.2 describes: an SRV
record `_jmap._tcp.example.com` pointing at the JMAP host, otherwise
`https://example.com/.well-known/jmap`. If your web site is not served by the mail server, add the
SRV record:

```
_jmap._tcp.example.com. 3600 IN SRV 0 1 443 mail.example.com.
```

The OAuth server is found from the JMAP host: RFC 9728 resource metadata, then RFC 8414 and OpenID
Connect discovery. It must be under the same registrable domain as the JMAP host (for example
`jmap.example.com` and `auth.example.com`); otherwise the bridge refuses the server.

**Client registration with Stalwart.** Nothing to do with the default settings: the bridge
registers itself as a public client with PKCE, which Stalwart accepts anonymously
(`anonymousClientRegistration`, on by default in Stalwart 0.16). Stalwart only issues confidential
clients to authenticated callers, so the bridge does not get a client secret this way; PKCE protects
the authorization code instead.

If the operator turned anonymous registration off, declare the client statically:

1. In Stalwart, Management › Directory › OAuth Clients, create a client with the redirect URI
   `https://mcp.example.com/callback` (and a secret if you want a confidential client).
2. Get the admin token of the bridge: `docker compose exec jmap-mcp /jmap-mcp admin-token` (or
   `jmap-mcp admin-token --data-dir /var/lib/jmap-mcp`).
3. Open `https://mcp.example.com/admin`, log in with any user name and the token as password, and
   enter the mail server (an email address or its URL), the client ID, the secret and the
   authentication method. They are stored encrypted in the bridge database.

The local mode needs dynamic registration of public clients, which is the Stalwart default.

## Configuration

Every option is optional and only concerns the deployment. Each flag can also be set with the
environment variable `JMAP_MCP_<FLAG>` (for example `JMAP_MCP_ENABLE_SEND=true`).

| Flag | Default | Purpose |
|---|---|---|
| `--listen` | `:8080` | HTTP listen address (`serve`). |
| `--data-dir` | `$XDG_CONFIG_HOME/jmap-mcp` (`/data` in the image) | Database and master key. |
| `--public-url` | from `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Prefix` | Public base URL of the bridge. |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error`. Logs never contain secrets, codes or email bodies. |
| `--enable-send` | `false` | Register `send_email`. |
| `--allow-private-networks` | `false` | Allow mail servers on private or loopback addresses (for example on the same LAN). It disables part of the SSRF protection. |

Commands: `jmap-mcp` or `jmap-mcp stdio` (local mode), `jmap-mcp serve` (HTTP mode),
`jmap-mcp admin-token`, `jmap-mcp healthcheck`, `jmap-mcp version`.

## Exposed endpoints

Everything below must be reachable through the reverse proxy, on the same host name.

| Path | Purpose |
|---|---|
| `/mcp` | MCP Streamable HTTP endpoint (bearer token required). |
| `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/mcp` | Protected resource metadata (RFC 9728). |
| `/.well-known/oauth-authorization-server`, `/.well-known/oauth-authorization-server/mcp` | Authorization server metadata (RFC 8414). |
| `/register` | Dynamic client registration (RFC 7591). |
| `/authorize` | Authorization endpoint and the page asking for the email address. |
| `/callback` | Return from the mail server's sign-in. |
| `/token` | Token endpoint (authorization code, refresh token). |
| `/revoke` | Token revocation (RFC 7009). |
| `/attachments/{token}` | Signed, short-lived attachment downloads. |
| `/admin` | Static client declaration (admin token required). |
| `/healthz` | Health check. |
| `/` | Short description page. |

## Security

- Only tokens issued by the bridge are accepted, and only for its own resource URL; mail-server
  tokens never leave the bridge. Issued tokens are opaque random values stored as keyed hashes.
  Access tokens last one hour; refresh tokens rotate on every use and only work for their client,
  and reusing an old one revokes the whole chain. Replaying an authorization code revokes the tokens
  issued from it.
- PKCE S256 is mandatory. Redirect URIs must be HTTPS, loopback HTTP or a private-use scheme, and
  match the registration exactly (any port for loopback). `state` is echoed and the `iss` parameter
  (RFC 9207) is sent and checked. On the mail-server leg, `state`, `iss` and the `nonce` of the ID
  token are checked, and the flow is bound to the browser with a cookie.
- A JMAP host can only send users to an authorization server of its own registrable domain, so a
  hostile domain cannot collect tokens issued by another mail server. The user is identified by the
  issuer and the `sub` of the ID token (nonce, issuer and audience checked), not by what the JMAP
  server reports. Mail tokens are only sent to the host they were requested for, never after a
  redirect to another host.
- Every outbound request (discovery, OAuth, JMAP, client metadata documents) goes through a guard
  that accepts only HTTPS, resolves the name and refuses private, loopback and link-local addresses
  at connection time, and limits redirects.
- Secrets are generated on first start: a master key in the data directory (or the OS keyring in
  local mode), from which the database encryption key (AES-GCM), the token hashing key and the
  attachment URL key are derived. Mail-server tokens and client secrets are encrypted at rest.
- The OAuth endpoints are rate limited per client IP; `X-Forwarded-For` is only trusted when the
  request comes from a private address, that is from your reverse proxy. HTML pages use no JavaScript and send a strict
  Content Security Policy, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. Attachments
  are always served as downloads (`application/octet-stream`, sandbox CSP).
- Sending email is off by default; when on, every message (full body and attachment names),
  permanent deletion, Sieve change and out-of-office change is confirmed by the user, and an
  approval only covers the exact content it showed. In local mode, connecting an account whose
  address came from the model is confirmed too. With clients that cannot elicit, the model must pass
  `confirm=true` after asking the user, as the specification requires; keep tool approval enabled in
  such clients, since a prompt-injected model could set it.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Data

The data directory holds `master.key` (unless the OS keyring is used) and `jmap-mcp.db` (SQLite).
Back up both together: the database cannot be decrypted without the key. Deleting them disconnects
every account; users simply sign in again.

## Development

```sh
go test ./...                                  # unit tests, including replayed Stalwart exchanges
go test -tags integration ./...                # starts Stalwart in Docker
golangci-lint run ./...
```

The integration tests start `stalwartlabs/stalwart`, complete its setup through its API, create
accounts, import sample messages and run the real OAuth flows (browser, device, HTTP bridge with
the MCP SDK client). The unit tests replay JMAP exchanges recorded from those runs; refresh them
with `JMAP_MCP_RECORD=$PWD/internal/tools/testdata/read go test -tags integration -run TestStalwartReadTools ./internal/tools`
(and `write` / `TestStalwartWriteTools`).

The layout: `internal/jmapc` (JMAP client and discovery), `internal/mailauth` (OAuth client of the
mail server), `internal/mailview` (compact email views), `internal/tools` (MCP tools),
`internal/stdio` and `internal/httpd` (the two modes), `internal/store` (encrypted SQLite),
`internal/netguard` (SSRF guard).

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Choice of JMAP library

| Library | Assessment |
|---|---|
| [`git.sr.ht/~rockorager/go-jmap`](https://git.sr.ht/~rockorager/go-jmap) | Used by aerc, covers core, mail and push. Last release v0.5.3 in February 2025, no Sieve. |
| [`github.com/mikluko/jmap`](https://github.com/mikluko/jmap) | Maintained fork of the above (v0.26.0, February 2026): same coverage, including EmailSubmission, Identity and VacationResponse, plus Sieve scripts (RFC 9661). **Chosen.** |
| [`github.com/rhyselsmore/go-jmap`](https://github.com/rhyselsmore/go-jmap) | Recent and well designed, but announced as "not yet usable" and without EmailSubmission or Identity. |

`mikluko/jmap` provides the method and object types. The transport is completed in
`internal/jmapc` without forking: its upload sends the wrong `Content-Type`, its download hardcodes
the name and type, and its session decoding fails on capabilities it does not know.

## Decisions

Points where the initial specification turned out to be inaccurate, or where a choice had to be
made, checked against the actual software in October 2026:

1. **Stalwart client registration.** The Stalwart reference gives `anonymousClientRegistration`
   a default of `true` (another page says `false`), and Stalwart 0.16.27 accepts anonymous
   registration, but only of public clients: a confidential client always needs an authenticated
   caller with the `oauthClientRegistration` permission. The bridge therefore asks for a
   confidential client, falls back to a public client with PKCE, and offers the `/admin` page for a
   statically declared client.
2. **Finding Stalwart's OAuth server.** Stalwart serves the JMAP session anonymously (HTTP 200) and
   only challenges API calls, and the session host found from the email domain can differ from the
   OAuth issuer (`example.com` versus `mail.example.com`). The bridge reads the RFC 9728 document at
   the session origin before trying RFC 8414 and OpenID discovery there.
3. **Elicitation with MCP 2026-07-28.** Go SDK v1.8.0 implements the 2026-07-28 protocol, which
   forbids server-initiated elicitation requests during a tool call: the server must return the
   questions in the result and the client retries (SEP-2322, multi round-trip requests). The tools
   use that mechanism and fall back to classic `elicitation/create` for clients on older versions.
4. **Registry name.** The registry grants `io.github.<owner>/*` with the exact case of the GitHub
   owner and compares names case-sensitively, so the server is published as
   `io.github.kOlapsis/jmap-mcp`, not `io.github.kolapsis/jmap-mcp`.
5. **Binary in the registry.** The registry has no plain binary package type. The binary is
   published as an MCP bundle (`.mcpb`: macOS universal and Windows x64, for Claude Desktop) and the
   image as an OCI package (local mode with a persistent volume, signing in with the device flow).
6. **Default account.** Asking which account to use on every call would make several accounts
   unusable. The account is asked once, when several are connected and none is the default, and
   the answer becomes the default (`list_accounts` changes it).
7. **Local token storage.** The local mode uses the same encrypted SQLite store as the HTTP mode;
   the OS keyring holds the master key rather than each token.
8. **Issued tokens.** Opaque tokens stored as keyed hashes rather than signed JWTs: they can be
   revoked, and refresh token reuse can be detected.
9. **Sieve and out-of-office.** Writing or activating a filtering rule can redirect or drop mail, and
   an automatic reply sends text to everyone who writes: both require the same confirmation as
   sending.
10. **Same-domain authorization server.** Following a JMAP host's metadata to any authorization
    server would let a hostile domain receive tokens issued by another server (and, in HTTP mode,
    claim another user's identity). The JMAP host and the issuer must share their registrable
    domain, and the user identity comes from the ID token. A provider whose JMAP host and OAuth
    server sit on unrelated domains is therefore not supported.

## Releasing

Every push to `main` builds the image and pushes `ghcr.io/kolapsis/jmap-mcp:main` (workflow
`image.yml`). Maintainers publish a version by pushing a `vX.Y.Z` tag. The release workflow runs GoReleaser (archives, checksums, SBOMs,
multi-arch image on GHCR with semver and `latest` tags, Homebrew cask pushed to
[kOlapsis/homebrew-tap](https://github.com/kOlapsis/homebrew-tap) with the deploy key stored in the
`HOMEBREW_TAP_DEPLOY_KEY` secret), builds and uploads `jmap-mcp.mcpb`, then publishes `server.json` to the MCP registry with
GitHub OIDC.

One-time setup: make the `jmap-mcp` package public in the organization's GitHub packages after the
first release (the registry only verifies public images), then re-run the `mcp-registry` job. Set
the repository topics so that directories such as Glama find it:

```sh
gh repo edit kOlapsis/jmap-mcp --description "MCP server giving AI assistants OAuth access to JMAP mailboxes (Stalwart and others)" \
  --homepage https://github.com/kOlapsis/jmap-mcp --add-topic mcp,mcp-server,jmap,stalwart,email
```

## License

[Apache-2.0](LICENSE)
