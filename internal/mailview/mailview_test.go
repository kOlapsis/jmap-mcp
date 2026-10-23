package mailview

import (
	"strings"
	"testing"
	"time"

	"github.com/mikluko/jmap"
	"github.com/mikluko/jmap/mail"
	"github.com/mikluko/jmap/mail/email"
)

func TestTruncate(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
		cut  bool
	}{
		{"hello", 10, "hello", false},
		{"hello", 0, "hello", false},
		{"héllo wörld", 4, "héll", true},
		{"☕☕☕", 2, "☕☕", true},
	} {
		got, cut := Truncate(c.in, c.max)
		if got != c.want || cut != c.cut {
			t.Errorf("Truncate(%q, %d) = %q, %v", c.in, c.max, got, cut)
		}
	}
}

func TestFlags(t *testing.T) {
	if got := Flags(map[string]bool{"$seen": true, "$flagged": true, "$answered": true}); strings.Join(got, ",") != "answered,flagged" {
		t.Errorf("flags = %v", got)
	}
	if got := Flags(nil); strings.Join(got, ",") != "unread" {
		t.Errorf("flags = %v", got)
	}
}

func TestFullConvertsHTMLAndTruncates(t *testing.T) {
	now := time.Date(2026, 10, 6, 10, 0, 0, 0, time.FixedZone("x", 3600))
	e := &email.Email{
		ID: "e1", ThreadID: "t1", MailboxIDs: map[jmap.ID]bool{"m1": true}, ReceivedAt: &now,
		From:        []*mail.Address{{Name: "News", Email: "news@example.org"}},
		To:          []*mail.Address{{Email: "alice@example.test"}},
		Subject:     "Weekly",
		HTMLBody:    []*email.BodyPart{{PartID: "1", Type: "text/html"}},
		TextBody:    []*email.BodyPart{{PartID: "1", Type: "text/html"}},
		BodyValues:  map[string]*email.BodyValue{"1": {Value: `<style>p{}</style><script>alert(1)</script><p>Hello &amp; <b>welcome</b></p><a href="javascript:x()">x</a>`}},
		Attachments: []*email.BodyPart{{BlobID: "b1", Name: "a.pdf", Type: "application/pdf", Size: 42}},
	}
	m := Full(e, map[jmap.ID]string{"m1": "Inbox"}, 9)
	if !m.BodyFromHTML || m.Body != "Hello & w" || !m.BodyTruncated || m.BodyLength < 15 {
		t.Fatalf("body: %+v", m)
	}
	if strings.Contains(m.Body, "alert") || m.From[0] != "News <news@example.org>" || m.To[0] != "alice@example.test" {
		t.Fatalf("message: %+v", m)
	}
	if m.ReceivedAt != "2026-10-06T09:00:00Z" || m.Mailboxes[0] != "Inbox" || m.Attachments[0].ID != "b1" {
		t.Fatalf("message: %+v", m)
	}
}

func TestSummarize(t *testing.T) {
	e := &email.Email{ID: "e1", ThreadID: "t1", Subject: "s", Keywords: map[string]bool{"$seen": true}, HasAttachment: true,
		MailboxIDs: map[jmap.ID]bool{"m1": true, "m2": false}}
	s := Summarize(e, map[jmap.ID]string{"m1": "Inbox", "m2": "Trash"})
	if s.Attachments != 1 || len(s.Flags) != 0 || len(s.Mailboxes) != 1 || s.Mailboxes[0] != "Inbox" {
		t.Fatalf("summary: %+v", s)
	}
}
