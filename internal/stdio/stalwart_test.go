//go:build integration

package stdio

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zalando/go-keyring"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/store"
	"github.com/kOlapsis/jmap-mcp/internal/testenv"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

func TestStalwartLocalAccounts(t *testing.T) {
	keyring.MockInit()
	sw := testenv.Start(t)
	alice := sw.CreateUser(t, "alice", "alice-password-1")
	bob := sw.CreateUser(t, "bob", "bob-password-1")
	cfg := &config.Config{DataDir: t.TempDir(), Net: sw.Net()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	m, err := newManager(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	m.browser = func(u string) error {
		go func() {
			redirect, err := sw.Authorize(u, alice, "alice-password-1")
			if err != nil {
				t.Error(err)
				return
			}
			resp, err := http.Get(redirect)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		}()
		return nil
	}
	b := &backend{cfg: cfg, log: log, mgr: m}
	srv := tools.New(tools.Options{Backend: b, Connector: m, Mode: "stdio"})
	m.onChange = func() { srv.Sync(ctx) }
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			if strings.Contains(req.Params.Message, "Which one") {
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"choice": bob}}, nil
			}
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"email": alice}}, nil
		},
	}).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Browser flow, with the address asked by elicitation.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "connect_account", Arguments: map[string]any{}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "connected") {
		t.Fatalf("connect_account: %v %+v", err, res)
	}
	tl, _ := cs.ListTools(ctx, nil)
	if !hasTool(tl, "list_identities") || !hasTool(tl, "vacation_response") || !hasTool(tl, "sieve_scripts") {
		t.Fatalf("optional tools not registered after connecting: %d tools", len(tl.Tools))
	}

	// Device flow.
	msg, err := m.Connect(ctx, bob, true)
	if err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`code ([A-Z0-9-]+)`).FindStringSubmatch(msg)
	if code == nil {
		t.Fatalf("no user code in %q", msg)
	}
	if err := sw.ApproveDevice(code[1], bob, "bob-password-1"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		accts, _ := m.Accounts(ctx)
		if len(accts) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("device flow did not complete: %d accounts", len(accts))
		}
		time.Sleep(time.Second)
	}

	// Two accounts and no default: the account is asked, then remembered.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_mailboxes", Arguments: map[string]any{}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, bob) {
		t.Fatalf("list_mailboxes after choosing: %v %+v", err, res)
	}
	res, _ = cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_accounts", Arguments: map[string]any{}})
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, `{"email":"`+bob+`","default":true}`) {
		t.Fatalf("default not remembered: %s", txt)
	}
	m.Close()

	// Restart: accounts survive, and an expired token is refreshed and saved.
	m, err = newManager(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	rows, _ := m.st.Accounts(ctx, store.LocalUser)
	if len(rows) != 2 {
		t.Fatalf("accounts after restart: %d", len(rows))
	}
	old := rows[0].Token.AccessToken
	expired := *rows[0].Token
	expired.Expiry = time.Now().Add(-time.Hour)
	if err := m.st.UpdateToken(ctx, rows[0].ID, &expired); err != nil {
		t.Fatal(err)
	}
	accts, _ := m.Accounts(ctx)
	for _, a := range accts {
		a.Client.Invalidate()
		if _, err := a.Client.MailAccount(ctx); err != nil {
			t.Fatalf("%s after refresh: %v", a.Email, err)
		}
	}
	rows, _ = m.st.Accounts(ctx, store.LocalUser)
	if rows[0].Token.AccessToken == old || !rows[0].Token.Valid() {
		t.Fatal("refreshed token was not saved")
	}
}

func hasTool(l *mcp.ListToolsResult, name string) bool {
	for _, t := range l.Tools {
		if t.Name == name {
			return true
		}
	}
	return false
}
