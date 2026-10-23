# Contributing

Thanks for your interest in jmap-mcp. Issues and pull requests are welcome.

## Before you start

- For a bug, open an issue with the steps to reproduce, the mail server (name and version) and the
  MCP client you use. Never paste tokens, passwords or email content.
- For a new feature, open an issue first. The tool surface is deliberately small (about fifteen
  tools); a new tool needs a strong reason.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Development

You need Go (the version in `go.mod`) and Docker for the integration tests.

```sh
go test ./...                         # unit tests
go test -tags integration ./...       # against Stalwart in Docker
golangci-lint run ./...
```

Integration tests start a disposable Stalwart container, configure it through its API and run the
real OAuth flows. Set `JMAP_MCP_KEEP_CONTAINER=1` to keep the container for inspection.

When a change alters the JMAP requests of the read or write scenarios, refresh the recorded
exchanges used by the unit tests:

```sh
JMAP_MCP_RECORD=$PWD/internal/tools/testdata/read  go test -tags integration -run TestStalwartReadTools  ./internal/tools
JMAP_MCP_RECORD=$PWD/internal/tools/testdata/write go test -tags integration -run TestStalwartWriteTools ./internal/tools
```

## Pull requests

- One change per pull request, with tests.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) in English
  (`feat:`, `fix:`, `docs:`...).
- Update `CHANGELOG.md` under "Unreleased" and the README when behavior or configuration changes.
- Keep the code plain: standard library first, no new dependency for a few lines, comments only for
  what the code cannot say.
- CI must pass: lint, unit and integration tests, cross-platform builds, `govulncheck`.

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
