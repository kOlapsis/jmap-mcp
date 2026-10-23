#!/bin/sh
# Builds the Claude Desktop bundle from the GoReleaser dist directory: scripts/build-mcpb.sh <version> [dist]
set -eu
version=$1
dist=${2:-dist}
out="$dist/jmap-mcp.mcpb"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/server"
cp "$dist"/jmap-mcp-darwin-universal_darwin_all/jmap-mcp "$work/server/jmap-mcp"
cp "$dist"/jmap-mcp_windows_amd64_v1/jmap-mcp.exe "$work/server/jmap-mcp.exe"
chmod 755 "$work/server/jmap-mcp"
jq --arg v "$version" '.version = $v' mcpb/manifest.json > "$work/manifest.json"
cp LICENSE "$work/"
rm -f "$out"
(cd "$work" && zip -qr -X "$OLDPWD/$out" .)
sha256sum "$out" | cut -d' ' -f1
