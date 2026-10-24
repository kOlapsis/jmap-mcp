// Package config parses the optional deployment settings.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

// Config holds deployment settings; every field has a working default.
type Config struct {
	Command    string
	DataDir    string
	Listen     string
	PublicURL  string
	LogLevel   slog.Level
	EnableSend bool
	Net        netguard.Options

	Args         []string
	ClientID     string
	ClientSecret string
	ClientAuth   string

	// Development and test only.
	DevToken      string
	DevSessionURL string
}

// EnvPrefix prefixes the environment variable form of every flag.
const EnvPrefix = "JMAP_MCP_"

// Parse reads flags, falling back to JMAP_MCP_* environment variables.
func Parse(args []string, stderr io.Writer) (*Config, error) {
	c := &Config{}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		c.Command, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("jmap-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var level, resolve string
	str := func(p *string, name, def, usage string) { fs.StringVar(p, name, env(name, def), usage) }
	boolean := func(p *bool, name, usage string) {
		v, _ := strconv.ParseBool(env(name, "false"))
		fs.BoolVar(p, name, v, usage)
	}
	str(&c.DataDir, "data-dir", "", "data directory (default: $XDG_CONFIG_HOME/jmap-mcp or OS equivalent)")
	str(&c.Listen, "listen", ":8080", "HTTP listen address of serve (default :8080)")
	str(&c.PublicURL, "public-url", "", "public base URL of the bridge (default: derived from X-Forwarded-* headers)")
	str(&level, "log-level", "info", "log level: debug, info (default), warn, error")
	boolean(&c.EnableSend, "enable-send", "allow sending email (always confirmed by the user)")
	boolean(&c.Net.AllowPrivate, "allow-private-networks", "allow mail servers on private or loopback addresses (disables part of the SSRF protection)")
	boolean(&c.Net.AllowHTTP, "dev-allow-http", "development only: accept plain http mail servers")
	boolean(&c.Net.InsecureTLS, "dev-insecure-tls", "development only: skip TLS certificate verification")
	str(&resolve, "dev-resolve", "", "development only: comma-separated host:port=ip:port overrides")
	str(&c.ClientID, "client-id", "", "client add: client ID declared at the authorization server")
	str(&c.ClientSecret, "client-secret", "", "client add: client secret, empty for a public client")
	str(&c.ClientAuth, "auth-method", "", "client add: none (default without secret), client_secret_basic (default with a secret) or client_secret_post")
	str(&c.DevToken, "dev-token", "", "development only: static JMAP bearer token (stdio)")
	str(&c.DevSessionURL, "dev-session-url", "", "development only: JMAP session URL used with --dev-token")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: jmap-mcp [stdio|serve|client add|admin-token|healthcheck|version] [flags]\n\n  stdio         MCP server on standard input and output (default)\n  serve         MCP server over HTTP with OAuth\n  client add <email or JMAP session URL> --client-id ID\n                declare a static OAuth client for the local mode\n  admin-token   print the token of the /admin page\n  healthcheck   exit 0 when the local HTTP server answers /healthz\n\nFlags (also read from %s<FLAG_NAME>):\n", EnvPrefix)
		fs.VisitAll(func(f *flag.Flag) {
			if !strings.HasPrefix(f.Name, "dev-") {
				fmt.Fprintf(stderr, "  --%s\n    \t%s\n", f.Name, f.Usage)
			}
		})
	}
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		c.Args, args = append(c.Args, fs.Arg(0)), fs.Args()[1:]
	}
	if err := c.LogLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	if resolve != "" {
		c.Net.Resolve = map[string]string{}
		for _, kv := range strings.Split(resolve, ",") {
			from, to, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if !ok {
				return nil, fmt.Errorf("invalid --dev-resolve entry %q", kv)
			}
			c.Net.Resolve[from] = to
		}
	}
	if (c.DevToken == "") != (c.DevSessionURL == "") {
		return nil, errors.New("--dev-token and --dev-session-url go together")
	}
	if c.DataDir == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("no data directory: pass --data-dir (%w)", err)
		}
		c.DataDir = filepath.Join(dir, "jmap-mcp")
	}
	return c, nil
}

func env(flagName, def string) string {
	if v, ok := os.LookupEnv(EnvPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))); ok {
		return v
	}
	return def
}
