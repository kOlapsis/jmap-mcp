package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/mikluko/jmap"
	"github.com/mikluko/jmap/mail/vacationresponse"
	"github.com/mikluko/jmap/sieve/sievescript"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
)

func (s *Server) registerVacation() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name: "vacation_response",
		Description: "Read the automatic out-of-office reply, or change it when any of enabled, subject, text_body, from_date or to_date is given. " +
			"Changes are confirmed by the user, since the reply is sent to everyone who writes.",
		Annotations: &mcp.ToolAnnotations{Title: "Out-of-office reply", IdempotentHint: true, DestructiveHint: ptr(false)},
	}, handler(s.vacation))
}

type vacationInput struct {
	Account  string  `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
	Enabled  *bool   `json:"enabled,omitempty" jsonschema:"turn the automatic reply on or off"`
	Subject  *string `json:"subject,omitempty" jsonschema:"subject of the reply"`
	TextBody *string `json:"text_body,omitempty" jsonschema:"plain-text body of the reply"`
	FromDate *string `json:"from_date,omitempty" jsonschema:"start (YYYY-MM-DD or RFC 3339); empty string to clear"`
	ToDate   *string `json:"to_date,omitempty" jsonschema:"end (YYYY-MM-DD or RFC 3339); empty string to clear"`
	Confirm  bool    `json:"confirm,omitempty" jsonschema:"only when the client cannot ask the user itself: set it after the user explicitly approved the change"`
}

func (s *Server) vacation(ctx context.Context, req *mcp.CallToolRequest, in vacationInput) (*mcp.CallToolResult, error) {
	d := newDialog(req)
	m, res, err := s.mail(ctx, d, in.Account)
	if err != nil || res != nil {
		return res, err
	}
	if !m.c.HasCapability(ctx, jmapc.CapVacation) {
		return nil, errors.New("this account does not support automatic replies")
	}
	patch := jmap.Patch{}
	if in.Enabled != nil {
		patch["isEnabled"] = *in.Enabled
	}
	if in.Subject != nil {
		patch["subject"] = *in.Subject
	}
	if in.TextBody != nil {
		patch["textBody"] = *in.TextBody
	}
	for name, v := range map[string]*string{"fromDate": in.FromDate, "toDate": in.ToDate} {
		if v == nil {
			continue
		}
		if *v == "" {
			patch[name] = nil
			continue
		}
		t, err := parseDate(*v)
		if err != nil {
			return nil, err
		}
		patch[name] = t.UTC().Format("2006-01-02T15:04:05Z")
	}
	if len(patch) > 0 {
		keys := make([]string, 0, len(patch))
		for k := range patch {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var lines []string
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("%s: %v", k, patch[k]))
		}
		msg := fmt.Sprintf("Change the automatic reply of %s? It is sent to everyone who writes to you.\n%s", m.acct.Email, strings.Join(lines, "\n"))
		if res, err := confirmOrArg(ctx, d, "confirm_vacation", msg, in.Confirm, "Changing the automatic reply"); err != nil || res != nil {
			return res, err
		}
	}
	r := &jmap.Request{}
	sid := ""
	if len(patch) > 0 {
		sid = r.Invoke(&vacationresponse.Set{Account: m.id, Update: map[jmap.ID]jmap.Patch{"singleton": patch}})
	}
	gid := r.Invoke(&vacationresponse.Get{Account: m.id, IDs: []jmap.ID{"singleton"}})
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	if sid != "" {
		set, err := jmapc.Result[*vacationresponse.SetResponse](resp, sid)
		if err != nil {
			return nil, err
		}
		if err := jmapc.SetErrors(set.NotUpdated); err != nil {
			return nil, err
		}
	}
	g, err := jmapc.Result[*vacationresponse.GetResponse](resp, gid)
	if err != nil {
		return nil, err
	}
	if len(g.List) == 0 {
		return nil, errors.New("the server returned no vacation response")
	}
	v := g.List[0]
	out := map[string]any{"account": m.acct.Email, "enabled": v.IsEnabled}
	if v.Subject != nil {
		out["subject"] = *v.Subject
	}
	if v.TextBody != nil {
		out["text_body"] = *v.TextBody
	}
	if v.FromDate != nil {
		out["from_date"] = v.FromDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	if v.ToDate != nil {
		out["to_date"] = v.ToDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	return text(out), nil
}

func (s *Server) registerSieve() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name: "sieve_scripts",
		Description: "Manage server-side filtering rules (Sieve scripts, RFC 9661): action list, get (id), put (name, content, optional id to replace, activate), " +
			"activate (id), deactivate or delete (id). Changes require the user's explicit confirmation, since a rule can redirect or discard mail.",
		Annotations: &mcp.ToolAnnotations{Title: "Filtering rules", DestructiveHint: ptr(true)},
	}, handler(s.sieve))
}

type sieveInput struct {
	Account  string `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
	Action   string `json:"action" jsonschema:"list, get, put, activate, deactivate or delete"`
	ID       string `json:"id,omitempty" jsonschema:"script id, for get, put (replace), activate and delete"`
	Name     string `json:"name,omitempty" jsonschema:"script name, for put"`
	Content  string `json:"content,omitempty" jsonschema:"Sieve source, for put"`
	Activate bool   `json:"activate,omitempty" jsonschema:"with put, make the script the active one"`
	Confirm  bool   `json:"confirm,omitempty" jsonschema:"only when the client cannot ask the user itself: set it after the user explicitly approved the change"`
}

func (s *Server) sieve(ctx context.Context, req *mcp.CallToolRequest, in sieveInput) (*mcp.CallToolResult, error) {
	d := newDialog(req)
	m, res, err := s.mail(ctx, d, in.Account)
	if err != nil || res != nil {
		return res, err
	}
	if !m.c.HasCapability(ctx, jmapc.CapSieve) {
		return nil, errors.New("this account does not support Sieve scripts")
	}
	scripts, err := m.sieveScripts(ctx)
	if err != nil {
		return nil, err
	}
	find := func() (*sievescript.SieveScript, error) {
		for _, sc := range scripts {
			if string(sc.ID) == in.ID {
				return sc, nil
			}
		}
		return nil, fmt.Errorf("unknown script %q", in.ID)
	}
	action := strings.ToLower(in.Action)
	switch action {
	case "list":
		out := make([]map[string]any, 0, len(scripts))
		for _, sc := range scripts {
			out = append(out, map[string]any{"id": sc.ID, "name": deref(sc.Name), "active": sc.IsActive})
		}
		return text(map[string]any{"account": m.acct.Email, "scripts": out}), nil
	case "get":
		sc, err := find()
		if err != nil {
			return nil, err
		}
		body, err := m.c.Download(ctx, m.id, sc.BlobID, deref(sc.Name)+".sieve", "application/sieve")
		if err != nil {
			return nil, err
		}
		defer body.Close()
		b, err := io.ReadAll(io.LimitReader(body, 1<<20))
		if err != nil {
			return nil, err
		}
		return text(map[string]any{"id": sc.ID, "name": deref(sc.Name), "active": sc.IsActive, "content": string(b)}), nil
	case "put", "activate", "deactivate", "delete":
	default:
		return nil, fmt.Errorf("unknown action %q", in.Action)
	}

	set := &sievescript.Set{Account: m.id}
	var msg string
	switch action {
	case "put":
		if in.Content == "" || (in.Name == "" && in.ID == "") {
			return nil, errors.New("put needs content and a name (or the id of the script to replace)")
		}
		msg = fmt.Sprintf("Save the Sieve script %q on %s%s?\n\n%s", in.Name, m.acct.Email, map[bool]string{true: " and make it active", false: ""}[in.Activate], in.Content)
	case "activate":
		sc, err := find()
		if err != nil {
			return nil, err
		}
		msg = fmt.Sprintf("Activate the Sieve script %q on %s?", deref(sc.Name), m.acct.Email)
		set.OnSuccessActivateScript = &sc.ID
	case "deactivate":
		msg = fmt.Sprintf("Deactivate the active Sieve script on %s?", m.acct.Email)
		set.OnSuccessDeactivateScript = true
	case "delete":
		sc, err := find()
		if err != nil {
			return nil, err
		}
		msg = fmt.Sprintf("Delete the Sieve script %q from %s? This cannot be undone.", deref(sc.Name), m.acct.Email)
		set.Destroy = []jmap.ID{sc.ID}
	}
	if res, err := confirmOrArg(ctx, d, "confirm_sieve", msg, in.Confirm, "Changing filtering rules"); err != nil || res != nil {
		return res, err
	}
	if action == "put" {
		up, err := m.c.Upload(ctx, m.id, "application/sieve", strings.NewReader(in.Content))
		if err != nil {
			return nil, err
		}
		r := &jmap.Request{}
		vid := r.Invoke(&sievescript.Validate{Account: m.id, BlobID: up.ID})
		resp, err := m.c.Do(ctx, r)
		if err != nil {
			return nil, err
		}
		v, err := jmapc.Result[*sievescript.ValidateResponse](resp, vid)
		if err != nil {
			return nil, err
		}
		if v.Error != nil {
			return nil, fmt.Errorf("invalid Sieve script: %s", deref(v.Error.Description))
		}
		target := jmap.ID("#new")
		if in.ID != "" {
			if _, err := find(); err != nil {
				return nil, err
			}
			p := jmap.Patch{"blobId": up.ID}
			if in.Name != "" {
				p["name"] = in.Name
			}
			set.Update = map[jmap.ID]jmap.Patch{jmap.ID(in.ID): p}
			target = jmap.ID(in.ID)
		} else {
			name := in.Name
			set.Create = map[jmap.ID]*sievescript.SieveScript{"new": {Name: &name, BlobID: up.ID}}
		}
		if in.Activate {
			set.OnSuccessActivateScript = &target
		}
	}
	r := &jmap.Request{}
	sid := r.Invoke(set)
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	out, err := jmapc.Result[*sievescript.SetResponse](resp, sid)
	if err != nil {
		return nil, err
	}
	if err := jmapc.SetErrors(out.NotCreated, out.NotUpdated, out.NotDestroyed); err != nil {
		return nil, err
	}
	result := map[string]any{"done": action}
	if c := out.Created["new"]; c != nil {
		result["id"] = c.ID
	}
	return text(result), nil
}

func (m *mailContext) sieveScripts(ctx context.Context) ([]*sievescript.SieveScript, error) {
	r := &jmap.Request{}
	gid := r.Invoke(&sievescript.Get{Account: m.id})
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	g, err := jmapc.Result[*sievescript.GetResponse](resp, gid)
	if err != nil {
		return nil, err
	}
	return g.List, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
