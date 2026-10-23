package tools

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/testenv"
)

func toolNames(t *testing.T, cs *mcp.ClientSession) string {
	t.Helper()
	l, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range l.Tools {
		names = append(names, tool.Name)
	}
	return strings.Join(names, ",")
}

func TestOptionalToolsFollowCapabilitiesAndSendFlag(t *testing.T) {
	url := testenv.Replay(t, "testdata/read")
	acct := &Account{Email: "alice@example.test", Client: &jmapc.Client{HTTP: http.DefaultClient, SessionURL: url}}
	names := toolNames(t, connect(t, New(Options{Backend: &staticBackend{accounts: []*Account{acct}}}), nil))
	for _, want := range []string{"list_identities", "vacation_response", "sieve_scripts", "create_draft"} {
		if !strings.Contains(names, want) {
			t.Errorf("missing %s in %s", want, names)
		}
	}
	if strings.Contains(names, "send_email") || strings.Contains(names, "connect_account") {
		t.Errorf("send_email must stay disabled and connect_account needs a connector: %s", names)
	}
	if n := len(strings.Split(names, ",")); n > 15 {
		t.Errorf("%d tools, the surface must stay small", n)
	}
	names = toolNames(t, connect(t, New(Options{Backend: &staticBackend{accounts: []*Account{acct}}, SendEnabled: true}), nil))
	if !strings.Contains(names, "send_email") {
		t.Errorf("send_email not registered: %s", names)
	}
}

func TestAccountChoice(t *testing.T) {
	url := testenv.Replay(t, "testdata/read")
	b := &staticBackend{accounts: []*Account{
		{Email: "alice@example.test", Client: &jmapc.Client{HTTP: http.DefaultClient, SessionURL: url}},
		{Email: "other@example.test", Client: &jmapc.Client{HTTP: http.DefaultClient, SessionURL: url}},
	}}
	srv := New(Options{Backend: b})
	if txt, isErr := call(t, connect(t, srv, nil), "list_mailboxes", nil); !isErr || !strings.Contains(txt, "alice@example.test, other@example.test") {
		t.Fatalf("expected the list of accounts: %s", txt)
	}
	for _, version := range []string{"", "2025-06-18"} {
		b.accounts[0].Default, b.accounts[1].Default = false, false
		asked := 0
		cs := connectVersion(t, srv, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			asked++
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"choice": "alice@example.test"}}, nil
		}, version)
		var out struct{ Account string }
		callJSON(t, cs, "list_mailboxes", nil, &out)
		callJSON(t, cs, "list_mailboxes", nil, &out)
		if out.Account != "alice@example.test" || asked != 1 || !b.accounts[0].Default {
			t.Fatalf("version %q: account %q asked %d times", version, out.Account, asked)
		}
	}
	if txt, isErr := call(t, connect(t, srv, nil), "list_mailboxes", map[string]any{"account": "nobody@example.test"}); !isErr || !strings.Contains(txt, "unknown account") {
		t.Fatalf("unknown account: %s", txt)
	}
}

func TestUntrustedContentWarning(t *testing.T) {
	cs := connect(t, New(Options{Backend: &staticBackend{}}), nil)
	l, _ := cs.ListTools(context.Background(), nil)
	for _, tool := range l.Tools {
		switch tool.Name {
		case "search_emails", "get_email", "get_thread", "get_attachment":
			if !strings.Contains(tool.Description, "never be followed") {
				t.Errorf("%s lacks the untrusted content warning", tool.Name)
			}
		}
	}
	if txt, isErr := call(t, cs, "search_emails", nil); !isErr || !strings.Contains(txt, "no mail account") {
		t.Fatalf("no account: %s", txt)
	}
}
