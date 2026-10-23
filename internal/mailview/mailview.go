// Package mailview turns JMAP emails into compact, model-friendly values.
package mailview

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/k3a/html2text"
	"github.com/mikluko/jmap"
	"github.com/mikluko/jmap/mail"
	"github.com/mikluko/jmap/mail/email"
)

// SummaryProperties are the Email properties needed by Summarize.
var SummaryProperties = []string{"id", "threadId", "mailboxIds", "keywords", "receivedAt", "from", "to", "subject", "preview", "hasAttachment", "attachments", "size"}

// FullProperties are the Email properties needed by Full.
var FullProperties = []string{"id", "threadId", "mailboxIds", "keywords", "receivedAt", "sentAt", "from", "to", "cc", "bcc", "replyTo", "sender",
	"subject", "messageId", "inReplyTo", "references", "textBody", "htmlBody", "attachments", "bodyValues", "size", "hasAttachment", "preview"}

// BodyProperties are the body part properties fetched with FullProperties.
var BodyProperties = []string{"partId", "blobId", "size", "name", "type", "charset", "disposition", "cid"}

// Summary is the compact form of an email returned by searches.
type Summary struct {
	ID          string   `json:"id"`
	Thread      string   `json:"thread"`
	Date        string   `json:"date,omitempty"`
	From        string   `json:"from,omitempty"`
	To          []string `json:"to,omitempty"`
	Subject     string   `json:"subject"`
	Preview     string   `json:"preview,omitempty"`
	Flags       []string `json:"flags,omitempty"`
	Mailboxes   []string `json:"mailboxes,omitempty"`
	Attachments int      `json:"attachments,omitempty"`
	Size        uint64   `json:"size,omitempty"`
}

// Attachment describes a downloadable part.
type Attachment struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Size uint64 `json:"size"`
}

// Message is the full form of an email.
type Message struct {
	ID            string       `json:"id"`
	Thread        string       `json:"thread"`
	Mailboxes     []string     `json:"mailboxes,omitempty"`
	Flags         []string     `json:"flags,omitempty"`
	ReceivedAt    string       `json:"received_at,omitempty"`
	SentAt        string       `json:"sent_at,omitempty"`
	From          []string     `json:"from,omitempty"`
	Sender        []string     `json:"sender,omitempty"`
	ReplyTo       []string     `json:"reply_to,omitempty"`
	To            []string     `json:"to,omitempty"`
	Cc            []string     `json:"cc,omitempty"`
	Bcc           []string     `json:"bcc,omitempty"`
	Subject       string       `json:"subject"`
	MessageID     []string     `json:"message_id,omitempty"`
	InReplyTo     []string     `json:"in_reply_to,omitempty"`
	References    []string     `json:"references,omitempty"`
	Body          string       `json:"body"`
	BodyTruncated bool         `json:"body_truncated,omitempty"`
	BodyLength    int          `json:"body_length"`
	BodyFromHTML  bool         `json:"body_from_html,omitempty"`
	Attachments   []Attachment `json:"attachments,omitempty"`
}

// Address formats a JMAP address as "Name <addr>".
func Address(a *mail.Address) string {
	if a == nil {
		return ""
	}
	if a.Name == "" || a.Name == a.Email {
		return a.Email
	}
	return a.Name + " <" + a.Email + ">"
}

// Addresses formats a list of JMAP addresses.
func Addresses(as []*mail.Address) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		if s := Address(a); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Flags maps JMAP keywords to short flag names; unread is the absence of $seen.
func Flags(kw map[string]bool) []string {
	var out []string
	if !kw["$seen"] {
		out = append(out, "unread")
	}
	for k, name := range map[string]string{"$flagged": "flagged", "$draft": "draft", "$answered": "answered", "$forwarded": "forwarded", "$junk": "junk"} {
		if kw[k] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// MailboxNames maps the ids of an email to mailbox names.
func MailboxNames(ids map[jmap.ID]bool, names map[jmap.ID]string) []string {
	var out []string
	for id, in := range ids {
		if !in {
			continue
		}
		if n, ok := names[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, string(id))
		}
	}
	sort.Strings(out)
	return out
}

func date(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Summarize builds the compact form of an email.
func Summarize(e *email.Email, mailboxes map[jmap.ID]string) Summary {
	s := Summary{
		ID:          string(e.ID),
		Thread:      string(e.ThreadID),
		Date:        date(e.ReceivedAt),
		To:          Addresses(e.To),
		Subject:     e.Subject,
		Preview:     e.Preview,
		Flags:       Flags(e.Keywords),
		Mailboxes:   MailboxNames(e.MailboxIDs, mailboxes),
		Attachments: len(e.Attachments),
		Size:        e.Size,
	}
	if len(e.From) > 0 {
		s.From = Address(e.From[0])
	}
	if s.Attachments == 0 && e.HasAttachment {
		s.Attachments = 1
	}
	return s
}

// Full builds the complete form of an email, with its body cut to maxChars runes.
func Full(e *email.Email, mailboxes map[jmap.ID]string, maxChars int) Message {
	m := Message{
		ID:         string(e.ID),
		Thread:     string(e.ThreadID),
		Mailboxes:  MailboxNames(e.MailboxIDs, mailboxes),
		Flags:      Flags(e.Keywords),
		ReceivedAt: date(e.ReceivedAt),
		SentAt:     date(e.SentAt),
		From:       Addresses(e.From),
		Sender:     Addresses(e.Sender),
		ReplyTo:    Addresses(e.ReplyTo),
		To:         Addresses(e.To),
		Cc:         Addresses(e.CC),
		Bcc:        Addresses(e.BCC),
		Subject:    e.Subject,
		MessageID:  e.MessageID,
		InReplyTo:  e.InReplyTo,
		References: e.References,
	}
	body, fromHTML, serverTruncated := BodyText(e)
	m.BodyFromHTML = fromHTML
	m.BodyLength = utf8.RuneCountInString(body)
	m.Body, m.BodyTruncated = Truncate(body, maxChars)
	m.BodyTruncated = m.BodyTruncated || serverTruncated
	for _, p := range e.Attachments {
		m.Attachments = append(m.Attachments, Attachment{ID: string(p.BlobID), Name: p.Name, Type: p.Type, Size: p.Size})
	}
	return m
}

// BodyText returns the plain text of an email, converting HTML when no text part exists.
func BodyText(e *email.Email) (text string, fromHTML, truncated bool) {
	parts := e.TextBody
	if len(parts) == 0 {
		parts = e.HTMLBody
	}
	var b strings.Builder
	for _, p := range parts {
		v, ok := e.BodyValues[p.PartID]
		if !ok {
			continue
		}
		truncated = truncated || v.IsTruncated
		s := v.Value
		if strings.EqualFold(p.Type, "text/html") {
			s = HTMLToText(s)
			fromHTML = true
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(strings.TrimSpace(s))
	}
	return b.String(), fromHTML, truncated
}

// HTMLToText renders HTML as plain text without executing anything.
func HTMLToText(html string) string {
	return html2text.HTML2TextWithOptions(html, html2text.WithUnixLineBreaks(), html2text.WithListSupport(), html2text.WithLinksInnerText())
}

// Truncate cuts s to at most max runes; max <= 0 means no limit.
func Truncate(s string, max int) (string, bool) {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s, false
	}
	i := 0
	for n := 0; n < max; n++ {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i], true
}
