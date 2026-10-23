// Command jmap-mcp is an MCP server giving AI assistants access to a JMAP mailbox.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/httpd"
	"github.com/kOlapsis/jmap-mcp/internal/stdio"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "jmap-mcp:", err)
		}
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		return err
	}
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = bi.Main.Version
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cfg.Command {
	case "", "stdio":
		return stdio.Run(ctx, cfg, version, log)
	case "healthcheck":
		return healthcheck(cfg.Listen)
	case "serve":
		srv, err := httpd.New(cfg, version, log)
		if err != nil {
			return err
		}
		defer srv.Close()
		return srv.Run(ctx)
	case "admin-token":
		srv, err := httpd.New(cfg, version, slog.New(slog.DiscardHandler))
		if err != nil {
			return err
		}
		defer srv.Close()
		fmt.Println(srv.AdminToken())
		return nil
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", cfg.Command)
	}
}

// healthcheck probes /healthz on the local listener; the distroless image has no curl.
func healthcheck(listen string) error {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: HTTP %d", resp.StatusCode)
	}
	return nil
}
