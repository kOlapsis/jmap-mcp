// Package stdio runs the MCP server for a local client over standard input and output.
package stdio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mikluko/jmap"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

const maxAttachmentFile = 200 << 20

// Run serves MCP on stdin/stdout until ctx ends or the client disconnects.
func Run(ctx context.Context, cfg *config.Config, version string, log *slog.Logger) error {
	b := &backend{cfg: cfg, log: log}
	var connector tools.Connector
	if cfg.DevToken != "" {
		hc := cfg.Net.Client(60 * time.Second)
		hc.Transport = &oauth2.Transport{Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.DevToken}), Base: hc.Transport}
		b.accounts = []*tools.Account{{Email: "dev", Client: &jmapc.Client{HTTP: hc, SessionURL: cfg.DevSessionURL}}}
	} else {
		mgr, err := newManager(cfg, log)
		if err != nil {
			return err
		}
		defer mgr.Close()
		b.mgr = mgr
		connector = mgr
	}
	srv := tools.New(tools.Options{Backend: b, Connector: connector, SendEnabled: cfg.EnableSend, Mode: "stdio", Version: version, Logger: log})
	if b.mgr != nil {
		b.mgr.onChange = func() { srv.Sync(context.WithoutCancel(ctx)) }
	}
	srv.Sync(ctx)
	defer b.cleanup()
	return srv.Run(ctx, &mcp.StdioTransport{})
}

type backend struct {
	cfg      *config.Config
	log      *slog.Logger
	mgr      *manager
	accounts []*tools.Account

	mu     sync.Mutex
	tmpDir string
}

func (b *backend) Accounts(ctx context.Context) ([]*tools.Account, error) {
	if b.mgr != nil {
		return b.mgr.Accounts(ctx)
	}
	return b.accounts, nil
}

func (b *backend) SetDefault(ctx context.Context, email string) error {
	if b.mgr != nil {
		return b.mgr.SetDefault(ctx, email)
	}
	return fmt.Errorf("unknown account %q", email)
}

// AttachmentLink saves the attachment in a private temporary directory and returns its path.
func (b *backend) AttachmentLink(ctx context.Context, _ *mcp.CallToolRequest, acct *tools.Account, accountID jmap.ID, att mailview.Attachment) (string, error) {
	b.mu.Lock()
	if b.tmpDir == "" {
		dir, err := os.MkdirTemp("", "jmap-mcp-")
		if err != nil {
			b.mu.Unlock()
			return "", err
		}
		b.tmpDir = dir
	}
	dir := b.tmpDir
	b.mu.Unlock()

	sum := sha256.Sum256([]byte(acct.Email + "\x00" + att.ID))
	path := filepath.Join(dir, hex.EncodeToString(sum[:6])+"-"+safeName(att.Name))
	body, err := acct.Client.Download(ctx, accountID, jmap.ID(att.ID), att.Name, att.Type)
	if err != nil {
		return "", err
	}
	defer body.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(body, maxAttachmentFile+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxAttachmentFile {
		err = fmt.Errorf("attachment larger than %d bytes", maxAttachmentFile)
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func (b *backend) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tmpDir != "" {
		_ = os.RemoveAll(b.tmpDir)
	}
}

func safeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." {
		return "attachment"
	}
	return name
}
