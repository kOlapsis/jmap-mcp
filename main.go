// Command jmap-mcp is an MCP server giving AI assistants access to a JMAP mailbox.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

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
	case "":
		return stdio.Run(ctx, cfg, version, log)
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
