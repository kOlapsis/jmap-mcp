package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kOlapsis/jmap-mcp/internal/mailview"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }

// elicitations answers every confirmation, and records the questions asked.
type elicitations struct{ asked []string }

func (e *elicitations) handle(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	e.asked = append(e.asked, req.Params.Message)
	b, _ := json.Marshal(req.Params.RequestedSchema)
	if strings.Contains(string(b), `"confirm"`) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"confirm": true}}, nil
	}
	return &mcp.ElicitResult{Action: "decline"}, nil
}

// writeScenario exercises the write tools; delivered reports whether bob received a subject (nil when replaying).
func writeScenario(t *testing.T, alice *Account, bob string, delivered func(subject string) bool) {
	b := &staticBackend{accounts: []*Account{alice}}
	srv := New(Options{Backend: b, Mode: "test", SendEnabled: true, Now: fixedNow})
	el := &elicitations{}
	modern := connect(t, srv, el.handle)
	legacy := connectVersion(t, srv, el.handle, "2025-11-25")
	plain := connect(t, srv, nil)

	var search struct {
		Total  int
		Emails []mailview.Summary
	}
	callJSON(t, modern, "search_emails", map[string]any{"subject": "Quarterly"}, &search)
	report := search.Emails[0].ID
	var upd struct{ Updated int }
	callJSON(t, modern, "update_emails", map[string]any{"ids": []string{report}, "read": true, "flagged": true}, &upd)
	callJSON(t, modern, "search_emails", map[string]any{"flagged": true, "unread": false}, &search)
	if upd.Updated != 1 || search.Total != 1 || search.Emails[0].ID != report {
		t.Fatalf("flags: %+v %+v", upd, search)
	}

	var moved struct{ Mailbox string }
	callJSON(t, modern, "move_emails", map[string]any{"ids": []string{report}, "mailbox": "junk"}, &moved)
	callJSON(t, modern, "search_emails", map[string]any{"mailbox": "junk"}, &search)
	if search.Total != 1 {
		t.Fatalf("move: %+v %+v", moved, search)
	}
	var folder, sub struct{ ID, Path string }
	callJSON(t, modern, "create_folder", map[string]any{"name": "Projects"}, &folder)
	callJSON(t, modern, "create_folder", map[string]any{"name": "2026", "parent": "Projects"}, &sub)
	callJSON(t, modern, "move_emails", map[string]any{"ids": []string{report}, "mailbox": "Projects/2026"}, &moved)
	callJSON(t, modern, "search_emails", map[string]any{"mailbox": sub.ID}, &search)
	if folder.Path != "Projects" || sub.Path != "Projects/2026" || moved.Mailbox != "Projects/2026" || search.Total != 1 {
		t.Fatalf("create_folder: %+v %+v %+v %+v", folder, sub, moved, search)
	}
	if txt, isErr := call(t, modern, "create_folder", map[string]any{"name": "x", "parent": "Nowhere"}); !isErr || !strings.Contains(txt, "unknown mailbox") {
		t.Fatalf("unknown parent accepted: %s", txt)
	}
	callJSON(t, modern, "delete_emails", map[string]any{"ids": []string{report}}, &moved)
	if !strings.EqualFold(moved.Mailbox, "Deleted Items") && !strings.EqualFold(moved.Mailbox, "Trash") {
		t.Fatalf("trash: %+v", moved)
	}
	if txt, isErr := call(t, plain, "delete_emails", map[string]any{"ids": []string{report}, "permanent": true}); !isErr || !strings.Contains(txt, "confirm=true") {
		t.Fatalf("permanent deletion without confirmation: %s", txt)
	}
	var destroyed struct{ Destroyed int }
	callJSON(t, legacy, "delete_emails", map[string]any{"ids": []string{report}, "permanent": true}, &destroyed)
	if destroyed.Destroyed != 1 || len(el.asked) != 1 || !strings.Contains(el.asked[0], "Quarterly report") {
		t.Fatalf("permanent deletion: %+v %q", destroyed, el.asked)
	}

	callJSON(t, modern, "search_emails", map[string]any{"subject": "Project kickoff", "sort": "oldest"}, &search)
	var draft struct {
		ID          string
		From, To    []string
		Cc          []string
		Subject     string
		Attachments int
	}
	callJSON(t, modern, "create_draft", map[string]any{"reply_to_email_id": search.Emails[0].ID, "reply_all": true, "body": "See you Friday.",
		"attachments": []map[string]any{{"name": "agenda.txt", "text": "1. Scope\n2. Planning\n"}}}, &draft)
	if draft.Subject != "Re: Project kickoff" || len(draft.To) != 1 || !strings.Contains(draft.To[0], "carol@example.org") ||
		len(draft.Cc) != 1 || !strings.Contains(draft.Cc[0], "dave@example.org") || draft.Attachments != 1 {
		t.Fatalf("reply draft: %+v", draft)
	}
	var msg mailview.Message
	callJSON(t, modern, "get_email", map[string]any{"id": draft.ID}, &msg)
	if len(msg.InReplyTo) != 1 || msg.InReplyTo[0] != "kickoff-1@example.org" || !strings.Contains(msg.Body, "> Can we meet on Friday") ||
		len(msg.Attachments) != 1 || msg.Thread != search.Emails[0].Thread || !strings.Contains(strings.Join(msg.Flags, ","), "draft") {
		t.Fatalf("reply draft content: %+v", msg)
	}

	if txt, isErr := call(t, plain, "send_email", map[string]any{"to": []string{bob}, "subject": "Lunch?", "body": "Noon?"}); !isErr || !strings.Contains(txt, "confirm=true") {
		t.Fatalf("send without confirmation: %s", txt)
	}
	var sent struct {
		Sent    bool
		EmailID string `json:"email_id"`
	}
	callJSON(t, modern, "send_email", map[string]any{"to": []string{"Bob <" + bob + ">"}, "subject": "Lunch?", "body": "Noon?"}, &sent)
	if !sent.Sent || !strings.Contains(el.asked[len(el.asked)-1], "Lunch?") {
		t.Fatalf("send: %+v %q", sent, el.asked)
	}
	callJSON(t, modern, "create_draft", map[string]any{"to": []string{bob}, "subject": "Draft then send", "body": "Hello"}, &draft)
	callJSON(t, plain, "send_email", map[string]any{"draft_id": draft.ID, "confirm": true}, &sent)
	callJSON(t, modern, "search_emails", map[string]any{"mailbox": "sent"}, &search)
	if search.Total != 2 {
		t.Fatalf("sent mailbox: %+v", search)
	}
	if delivered != nil {
		deadline := time.Now().Add(20 * time.Second)
		for !delivered("Lunch?") || !delivered("Draft then send") {
			if time.Now().After(deadline) {
				t.Fatal("bob did not receive the messages")
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	var vac struct {
		Enabled bool
		Subject string
	}
	callJSON(t, modern, "vacation_response", map[string]any{"enabled": true, "subject": "Away", "text_body": "Back on Monday", "to_date": "2026-12-01"}, &vac)
	if !vac.Enabled || vac.Subject != "Away" {
		t.Fatalf("vacation: %+v", vac)
	}

	script := "require \"fileinto\";\nif header :contains \"subject\" \"newsletter\" { fileinto \"Archive\"; }\n"
	if txt, isErr := call(t, modern, "sieve_scripts", map[string]any{"action": "put", "name": "bad", "content": "if broken {"}); !isErr || !strings.Contains(txt, "invalid Sieve") {
		t.Fatalf("invalid script accepted: %s", txt)
	}
	var put struct{ ID string }
	callJSON(t, modern, "sieve_scripts", map[string]any{"action": "put", "name": "newsletters", "content": script, "activate": true}, &put)
	var scripts struct {
		Scripts []struct {
			ID, Name string
			Active   bool
		}
	}
	callJSON(t, modern, "sieve_scripts", map[string]any{"action": "list"}, &scripts)
	found := false
	for _, s := range scripts.Scripts {
		found = found || (s.Name == "newsletters" && s.Active && s.ID == put.ID)
	}
	var got struct{ Content string }
	callJSON(t, modern, "sieve_scripts", map[string]any{"action": "get", "id": put.ID}, &got)
	if !found || got.Content != script {
		t.Fatalf("sieve: %+v %q", scripts, got.Content)
	}
	callJSON(t, modern, "sieve_scripts", map[string]any{"action": "deactivate"}, &put)
	callJSON(t, modern, "sieve_scripts", map[string]any{"action": "delete", "id": scripts.Scripts[len(scripts.Scripts)-1].ID}, &put)
}
