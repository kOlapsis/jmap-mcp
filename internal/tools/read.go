package tools

import (
	"context"
	"fmt"
	"io"
	"mime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mikluko/jmap"
	"github.com/mikluko/jmap/mail/email"
	"github.com/mikluko/jmap/mail/mailbox"
	"github.com/mikluko/jmap/mail/thread"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
)

const (
	defaultLimit   = 20
	maxLimit       = 100
	defaultBodyLen = 10000
	maxBodyLen     = 200000
	inlineTextMax  = 512 << 10
	inlineImageMax = 1 << 20
)

// mailboxes fetches all mailboxes of the account.
func (m *mailContext) mailboxes(ctx context.Context) ([]*mailbox.Mailbox, error) {
	req := &jmap.Request{}
	id := req.Invoke(&mailbox.Get{Account: m.id})
	resp, err := m.c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	r, err := jmapc.Result[*mailbox.GetResponse](resp, id)
	if err != nil {
		return nil, err
	}
	return r.List, nil
}

// mailboxPaths maps mailbox ids to "Parent/Child" paths.
func mailboxPaths(list []*mailbox.Mailbox) map[jmap.ID]string {
	byID := make(map[jmap.ID]*mailbox.Mailbox, len(list))
	for _, mb := range list {
		byID[mb.ID] = mb
	}
	paths := make(map[jmap.ID]string, len(list))
	for _, mb := range list {
		parts := []string{mb.Name}
		seen := map[jmap.ID]bool{mb.ID: true}
		for p := byID[mb.ParentID]; p != nil && !seen[p.ID]; p = byID[p.ParentID] {
			seen[p.ID] = true
			parts = append([]string{p.Name}, parts...)
		}
		paths[mb.ID] = strings.Join(parts, "/")
	}
	return paths
}

// findMailbox resolves a mailbox by id, role, path or name.
func findMailbox(list []*mailbox.Mailbox, ref string) (*mailbox.Mailbox, error) {
	ref = strings.TrimSpace(ref)
	paths := mailboxPaths(list)
	for _, match := range []func(*mailbox.Mailbox) bool{
		func(mb *mailbox.Mailbox) bool { return string(mb.ID) == ref },
		func(mb *mailbox.Mailbox) bool { return strings.EqualFold(string(mb.Role), ref) },
		func(mb *mailbox.Mailbox) bool { return strings.EqualFold(paths[mb.ID], ref) },
		func(mb *mailbox.Mailbox) bool { return strings.EqualFold(mb.Name, ref) },
	} {
		for _, mb := range list {
			if match(mb) {
				return mb, nil
			}
		}
	}
	names := make([]string, 0, len(list))
	for _, mb := range list {
		names = append(names, paths[mb.ID])
	}
	sort.Strings(names)
	return nil, fmt.Errorf("unknown mailbox %q; available: %s", ref, strings.Join(names, ", "))
}

func (s *Server) registerReadTools() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "list_mailboxes",
		Description: "List the mailboxes (folders) of an account with their role (inbox, sent, drafts, trash, archive, junk), path, total and unread counts.",
		Annotations: readOnly("List mailboxes"),
	}, handler(s.listMailboxes))

	mcp.AddTool(s.Server, &mcp.Tool{
		Name: "search_emails",
		Description: "Search emails by text, sender, recipient, subject, mailbox, date range, unread or flagged state, attachments and size. " +
			"Returns compact summaries (id, thread, date, from, subject, preview, flags, attachment count) with pagination." + untrusted,
		Annotations: readOnly("Search emails"),
	}, handler(s.searchEmails))

	mcp.AddTool(s.Server, &mcp.Tool{
		Name: "get_email",
		Description: "Get one email: useful headers, plain-text body (HTML converted when there is no text version, cut to max_body_length with body_truncated set) " +
			"and the list of attachments (id, name, type, size)." + untrusted,
		Annotations: readOnly("Read email"),
	}, handler(s.getEmail))

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "get_thread",
		Description: "Get the emails of a conversation in chronological order, as summaries or (full=true) complete messages." + untrusted,
		Annotations: readOnly("Read conversation"),
	}, handler(s.getThread))

	mcp.AddTool(s.Server, &mcp.Tool{
		Name: "get_attachment",
		Description: "Get an attachment of an email. Text and small images are returned inline; " +
			"larger or binary files are returned as a short-lived download link or a local file path." + untrusted,
		Annotations: readOnly("Get attachment"),
	}, handler(s.getAttachment))
}

type listMailboxesInput struct {
	Account string `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
}

type mailboxView struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Role   string `json:"role,omitempty"`
	Total  uint64 `json:"total"`
	Unread uint64 `json:"unread"`
}

func (s *Server) listMailboxes(ctx context.Context, req *mcp.CallToolRequest, in listMailboxesInput) (*mcp.CallToolResult, error) {
	m, res, err := s.mail(ctx, newDialog(req), in.Account)
	if err != nil || res != nil {
		return res, err
	}
	list, err := m.mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	paths := mailboxPaths(list)
	out := make([]mailboxView, 0, len(list))
	for _, mb := range list {
		out = append(out, mailboxView{ID: string(mb.ID), Path: paths[mb.ID], Role: string(mb.Role), Total: mb.TotalEmails, Unread: mb.UnreadEmails})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return text(map[string]any{"account": m.acct.Email, "mailboxes": out}), nil
}

type searchInput struct {
	Account       string `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
	Text          string `json:"text,omitempty" jsonschema:"full-text search in headers and body"`
	From          string `json:"from,omitempty" jsonschema:"sender address or name contains"`
	To            string `json:"to,omitempty" jsonschema:"recipient (To, Cc or Bcc) contains"`
	Subject       string `json:"subject,omitempty" jsonschema:"subject contains"`
	Mailbox       string `json:"mailbox,omitempty" jsonschema:"restrict to a mailbox: id, role (inbox, sent, drafts, trash, archive, junk) or name"`
	After         string `json:"after,omitempty" jsonschema:"received at or after this date (YYYY-MM-DD or RFC 3339)"`
	Before        string `json:"before,omitempty" jsonschema:"received before this date (YYYY-MM-DD or RFC 3339)"`
	Unread        *bool  `json:"unread,omitempty" jsonschema:"true for unread emails only, false for read emails only"`
	Flagged       *bool  `json:"flagged,omitempty" jsonschema:"true for flagged emails only, false for unflagged only"`
	HasAttachment bool   `json:"has_attachment,omitempty" jsonschema:"only emails with attachments"`
	MinSize       uint64 `json:"min_size,omitempty" jsonschema:"minimum size in bytes"`
	MaxSize       uint64 `json:"max_size,omitempty" jsonschema:"maximum size in bytes"`
	Sort          string `json:"sort,omitempty" jsonschema:"newest (default), oldest, largest, smallest, sender or subject"`
	Position      int64  `json:"position,omitempty" jsonschema:"zero-based index of the first result"`
	Limit         uint64 `json:"limit,omitempty" jsonschema:"number of results, default 20, maximum 100"`
}

func parseDate(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("invalid date %q: use YYYY-MM-DD or RFC 3339", s)
}

var sorts = map[string]*email.SortComparator{
	"":         {Property: "receivedAt"},
	"newest":   {Property: "receivedAt"},
	"oldest":   {Property: "receivedAt", IsAscending: true},
	"largest":  {Property: "size"},
	"smallest": {Property: "size", IsAscending: true},
	"sender":   {Property: "from", IsAscending: true},
	"subject":  {Property: "subject", IsAscending: true},
}

func clampLimit(l uint64) uint64 {
	if l == 0 {
		return defaultLimit
	}
	return min(l, maxLimit)
}

func (s *Server) searchEmails(ctx context.Context, req *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, error) {
	m, res, err := s.mail(ctx, newDialog(req), in.Account)
	if err != nil || res != nil {
		return res, err
	}
	sortBy, ok := sorts[strings.ToLower(in.Sort)]
	if !ok {
		return nil, fmt.Errorf("invalid sort %q", in.Sort)
	}
	cond := &email.FilterCondition{Text: in.Text, From: in.From, To: in.To, Subject: in.Subject,
		HasAttachment: in.HasAttachment, MinSize: in.MinSize, MaxSize: in.MaxSize}
	if cond.After, err = parseDate(in.After); err != nil {
		return nil, err
	}
	if cond.Before, err = parseDate(in.Before); err != nil {
		return nil, err
	}
	list, err := m.mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	if in.Mailbox != "" {
		mb, err := findMailbox(list, in.Mailbox)
		if err != nil {
			return nil, err
		}
		cond.InMailbox = mb.ID
	}
	conds := []email.Filter{cond}
	keyword := func(kw string, want *bool, invert bool) {
		if want == nil {
			return
		}
		if *want != invert {
			conds = append(conds, &email.FilterCondition{HasKeyword: kw})
		} else {
			conds = append(conds, &email.FilterCondition{NotKeyword: kw})
		}
	}
	keyword("$seen", in.Unread, true)
	keyword("$flagged", in.Flagged, false)
	var filter email.Filter = cond
	if len(conds) > 1 {
		filter = &email.FilterOperator{Operator: jmap.OperatorAND, Conditions: conds}
	}

	limit := clampLimit(in.Limit)
	r := &jmap.Request{}
	qid := r.Invoke(&email.Query{Account: m.id, Filter: filter, Sort: []*email.SortComparator{sortBy},
		Position: max(in.Position, 0), Limit: limit, CalculateTotal: true})
	gid := r.Invoke(&email.Get{Account: m.id, Properties: mailview.SummaryProperties, BodyProperties: []string{"blobId"},
		ReferenceIDs: &jmap.ResultReference{ResultOf: qid, Name: "Email/query", Path: "/ids"}})
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	q, err := jmapc.Result[*email.QueryResponse](resp, qid)
	if err != nil {
		return nil, err
	}
	g, err := jmapc.Result[*email.GetResponse](resp, gid)
	if err != nil {
		return nil, err
	}
	paths := mailboxPaths(list)
	byID := make(map[jmap.ID]*email.Email, len(g.List))
	for _, e := range g.List {
		byID[e.ID] = e
	}
	out := make([]mailview.Summary, 0, len(q.IDs))
	for _, id := range q.IDs {
		if e := byID[id]; e != nil {
			out = append(out, mailview.Summarize(e, paths))
		}
	}
	result := map[string]any{"account": m.acct.Email, "position": q.Position, "total": q.Total, "emails": out}
	if next := q.Position + uint64(len(q.IDs)); next < q.Total {
		result["next_position"] = next
	}
	return text(result), nil
}

type getEmailInput struct {
	Account       string `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
	ID            string `json:"id" jsonschema:"email id"`
	MaxBodyLength int    `json:"max_body_length,omitempty" jsonschema:"maximum body length in characters, default 10000"`
}

func bodyLimit(n int) int {
	if n <= 0 {
		return defaultBodyLen
	}
	return min(n, maxBodyLen)
}

// fetchFull gets complete emails in the given order.
func (m *mailContext) fetchFull(ctx context.Context, ids []jmap.ID, maxChars int) ([]*email.Email, error) {
	r := &jmap.Request{}
	gid := r.Invoke(&email.Get{Account: m.id, IDs: ids, Properties: mailview.FullProperties, BodyProperties: mailview.BodyProperties,
		FetchTextBodyValues: true, FetchHTMLBodyValues: true, MaxBodyValueBytes: uint64(maxChars)*4 + 1024})
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	g, err := jmapc.Result[*email.GetResponse](resp, gid)
	if err != nil {
		return nil, err
	}
	byID := make(map[jmap.ID]*email.Email, len(g.List))
	for _, e := range g.List {
		byID[e.ID] = e
	}
	out := make([]*email.Email, 0, len(ids))
	for _, id := range ids {
		if e := byID[id]; e != nil {
			out = append(out, e)
		}
	}
	if len(out) == 0 && len(ids) > 0 {
		return nil, fmt.Errorf("email %s not found", ids[0])
	}
	return out, nil
}

func (s *Server) getEmail(ctx context.Context, req *mcp.CallToolRequest, in getEmailInput) (*mcp.CallToolResult, error) {
	m, res, err := s.mail(ctx, newDialog(req), in.Account)
	if err != nil || res != nil {
		return res, err
	}
	limit := bodyLimit(in.MaxBodyLength)
	list, err := m.mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	es, err := m.fetchFull(ctx, []jmap.ID{jmap.ID(in.ID)}, limit)
	if err != nil {
		return nil, err
	}
	return text(mailview.Full(es[0], mailboxPaths(list), limit)), nil
}

type getThreadInput struct {
	Account       string `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
	ThreadID      string `json:"thread_id" jsonschema:"thread id (the thread field of an email)"`
	Full          bool   `json:"full,omitempty" jsonschema:"return complete messages instead of summaries"`
	MaxBodyLength int    `json:"max_body_length,omitempty" jsonschema:"with full=true, maximum body length per message in characters, default 10000"`
	Position      int    `json:"position,omitempty" jsonschema:"zero-based index of the first message"`
	Limit         uint64 `json:"limit,omitempty" jsonschema:"number of messages, default 20, maximum 100"`
}

func (s *Server) getThread(ctx context.Context, req *mcp.CallToolRequest, in getThreadInput) (*mcp.CallToolResult, error) {
	m, res, err := s.mail(ctx, newDialog(req), in.Account)
	if err != nil || res != nil {
		return res, err
	}
	r := &jmap.Request{}
	tid := r.Invoke(&thread.Get{Account: m.id, IDs: []jmap.ID{jmap.ID(in.ThreadID)}})
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	t, err := jmapc.Result[*thread.GetResponse](resp, tid)
	if err != nil {
		return nil, err
	}
	if len(t.List) == 0 {
		return nil, fmt.Errorf("thread %s not found", in.ThreadID)
	}
	all := t.List[0].EmailIDs
	start := min(max(in.Position, 0), len(all))
	ids := all[start:min(start+int(clampLimit(in.Limit)), len(all))]
	list, err := m.mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	paths := mailboxPaths(list)
	result := map[string]any{"thread": in.ThreadID, "total": len(all), "position": start}
	if end := start + len(ids); end < len(all) {
		result["next_position"] = end
	}
	if len(ids) == 0 {
		result["emails"] = []any{}
		return text(result), nil
	}
	if in.Full {
		limit := bodyLimit(in.MaxBodyLength)
		es, err := m.fetchFull(ctx, ids, limit)
		if err != nil {
			return nil, err
		}
		msgs := make([]mailview.Message, len(es))
		for i, e := range es {
			msgs[i] = mailview.Full(e, paths, limit)
		}
		result["emails"] = msgs
		return text(result), nil
	}
	r = &jmap.Request{}
	gid := r.Invoke(&email.Get{Account: m.id, IDs: ids, Properties: mailview.SummaryProperties, BodyProperties: []string{"blobId"}})
	resp, err = m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	g, err := jmapc.Result[*email.GetResponse](resp, gid)
	if err != nil {
		return nil, err
	}
	byID := make(map[jmap.ID]*email.Email, len(g.List))
	for _, e := range g.List {
		byID[e.ID] = e
	}
	sums := make([]mailview.Summary, 0, len(ids))
	for _, id := range ids {
		if e := byID[id]; e != nil {
			sums = append(sums, mailview.Summarize(e, paths))
		}
	}
	result["emails"] = sums
	return text(result), nil
}

type getAttachmentInput struct {
	Account      string `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
	EmailID      string `json:"email_id" jsonschema:"id of the email holding the attachment"`
	AttachmentID string `json:"attachment_id" jsonschema:"attachment id as listed by get_email"`
	MaxLength    int    `json:"max_length,omitempty" jsonschema:"for text attachments, maximum length in characters, default 10000"`
}

func isText(t string) bool {
	mt, _, _ := mime.ParseMediaType(t)
	return strings.HasPrefix(mt, "text/") || mt == "message/rfc822" || mt == "application/json" || mt == "application/xml" ||
		strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")
}

func (s *Server) getAttachment(ctx context.Context, req *mcp.CallToolRequest, in getAttachmentInput) (*mcp.CallToolResult, error) {
	m, res, err := s.mail(ctx, newDialog(req), in.Account)
	if err != nil || res != nil {
		return res, err
	}
	r := &jmap.Request{}
	gid := r.Invoke(&email.Get{Account: m.id, IDs: []jmap.ID{jmap.ID(in.EmailID)}, Properties: []string{"id", "attachments"},
		BodyProperties: []string{"blobId", "name", "type", "size"}})
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	g, err := jmapc.Result[*email.GetResponse](resp, gid)
	if err != nil {
		return nil, err
	}
	if len(g.List) == 0 {
		return nil, fmt.Errorf("email %s not found", in.EmailID)
	}
	var att *mailview.Attachment
	for _, p := range g.List[0].Attachments {
		if string(p.BlobID) == in.AttachmentID {
			att = &mailview.Attachment{ID: string(p.BlobID), Name: p.Name, Type: p.Type, Size: p.Size}
			break
		}
	}
	if att == nil {
		return nil, fmt.Errorf("attachment %s not found in email %s", in.AttachmentID, in.EmailID)
	}
	mt, _, _ := mime.ParseMediaType(att.Type)
	inline := (isText(att.Type) && att.Size <= inlineTextMax) || (strings.HasPrefix(mt, "image/") && att.Size <= inlineImageMax)
	if !inline {
		link, err := s.opts.Backend.AttachmentLink(ctx, req, m.acct, m.id, *att)
		if err != nil {
			return nil, err
		}
		return text(map[string]any{"name": att.Name, "type": att.Type, "size": att.Size, "location": link}), nil
	}
	body, err := m.c.Download(ctx, m.id, jmap.ID(att.ID), att.Name, att.Type)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, max(inlineTextMax, inlineImageMax)+1))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(mt, "image/") {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.ImageContent{Data: data, MIMEType: mt}}}, nil
	}
	if !utf8.Valid(data) {
		data = []byte(strings.ToValidUTF8(string(data), "�"))
	}
	content, truncated := mailview.Truncate(string(data), bodyLimit(in.MaxLength))
	return text(map[string]any{"name": att.Name, "type": att.Type, "size": att.Size, "content": content, "truncated": truncated}), nil
}
