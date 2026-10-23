package tools

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
	"github.com/kOlapsis/jmap-mcp/internal/testenv"
)

// TestReadToolsReplay runs the read scenario against JMAP exchanges recorded from Stalwart
// (refresh them with: JMAP_MCP_RECORD=$PWD/internal/tools/testdata/read go test -tags integration -run TestStalwartReadTools ./internal/tools).
func TestReadToolsReplay(t *testing.T) {
	url := testenv.Replay(t, "testdata/read")
	readScenario(t, &Account{Email: "alice@example.test", Client: &jmapc.Client{HTTP: http.DefaultClient, SessionURL: url}})
}

func readScenario(t *testing.T, acct *Account) {
	b := &staticBackend{accounts: []*Account{acct}}
	cs := connect(t, New(Options{Backend: b, Mode: "test"}), nil)

	var mbs struct {
		Mailboxes []struct {
			ID, Path, Role string
			Total, Unread  int
		}
	}
	callJSON(t, cs, "list_mailboxes", nil, &mbs)
	inbox := false
	for _, m := range mbs.Mailboxes {
		inbox = inbox || (m.Role == "inbox" && m.Total == len(testenv.Fixtures) && m.Unread == len(testenv.Fixtures))
	}
	if !inbox {
		t.Fatalf("inbox counts: %+v", mbs)
	}

	var search struct {
		Total  int
		Emails []mailview.Summary
	}
	callJSON(t, cs, "search_emails", map[string]any{"mailbox": "inbox", "limit": 2}, &search)
	if search.Total != len(testenv.Fixtures) || len(search.Emails) != 2 || !strings.Contains(search.Emails[0].Subject, "Réunion") {
		t.Fatalf("search: %+v", search)
	}
	callJSON(t, cs, "search_emails", map[string]any{"subject": "kickoff", "sort": "oldest"}, &search)
	if search.Total != 2 || search.Emails[0].Thread != search.Emails[1].Thread {
		t.Fatalf("thread search: %+v", search)
	}

	var thread struct {
		Total  int
		Emails []mailview.Message
	}
	callJSON(t, cs, "get_thread", map[string]any{"thread_id": search.Emails[0].Thread, "full": true}, &thread)
	if thread.Total != 2 || !strings.Contains(thread.Emails[1].Body, "Friday works") {
		t.Fatalf("thread: %+v", thread)
	}

	callJSON(t, cs, "search_emails", map[string]any{"from": "news@example.org"}, &search)
	var msg mailview.Message
	callJSON(t, cs, "get_email", map[string]any{"id": search.Emails[0].ID}, &msg)
	if !msg.BodyFromHTML || !strings.Contains(msg.Body, "Hello & welcome") || strings.Contains(msg.Body, "alert(1)") {
		t.Fatalf("html email: %+v", msg)
	}

	callJSON(t, cs, "search_emails", map[string]any{"has_attachment": true}, &search)
	if len(search.Emails) != 1 || search.Emails[0].Attachments != 2 {
		t.Fatalf("attachment search: %+v", search)
	}
	callJSON(t, cs, "get_email", map[string]any{"id": search.Emails[0].ID, "max_body_length": 5}, &msg)
	if len(msg.Attachments) != 2 || !msg.BodyTruncated || msg.Body != "See t" {
		t.Fatalf("attachments: %+v", msg)
	}
	var att struct{ Content string }
	callJSON(t, cs, "get_attachment", map[string]any{"email_id": msg.ID, "attachment_id": msg.Attachments[0].ID}, &att)
	if !strings.Contains(att.Content, "Line two") {
		t.Fatalf("text attachment: %+v", att)
	}
	if txt, _ := call(t, cs, "get_attachment", map[string]any{"email_id": msg.ID, "attachment_id": msg.Attachments[1].ID}); txt != "image:image/png" {
		t.Fatalf("image attachment: %s", txt)
	}
}
