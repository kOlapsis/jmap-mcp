package tools

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/mikluko/jmap"
	"github.com/mikluko/jmap/mail/identity"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
)

func (s *Server) registerAccountTools() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "list_accounts",
		Description: "List the connected mail accounts and the default one. Pass set_default to change the default account.",
		Annotations: &mcp.ToolAnnotations{Title: "List accounts", IdempotentHint: true},
	}, handler(s.listAccounts))

	if s.opts.Connector == nil {
		return
	}
	mcp.AddTool(s.Server, &mcp.Tool{
		Name: "connect_account",
		Description: "Connect a mail account from its email address. The server finds the mail server automatically and the user signs in " +
			"in their browser, on the mail server's own page; never ask the user for a password. Set device_flow when the browser is on another machine.",
		Annotations: &mcp.ToolAnnotations{Title: "Connect account", OpenWorldHint: ptr(true)},
	}, handler(s.connectAccount))
}

type listAccountsInput struct {
	SetDefault string `json:"set_default,omitempty" jsonschema:"email address of a connected account to make the default"`
}

func (s *Server) listAccounts(ctx context.Context, _ *mcp.CallToolRequest, in listAccountsInput) (*mcp.CallToolResult, error) {
	if in.SetDefault != "" {
		if err := s.opts.Backend.SetDefault(ctx, in.SetDefault); err != nil {
			return nil, err
		}
	}
	accts, err := s.opts.Backend.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	type view struct {
		Email   string `json:"email"`
		Default bool   `json:"default,omitempty"`
	}
	out := make([]view, 0, len(accts))
	for _, a := range accts {
		out = append(out, view{Email: a.Email, Default: a.Default || len(accts) == 1})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return text(map[string]any{"accounts": out}), nil
}

type connectInput struct {
	Email      string `json:"email,omitempty" jsonschema:"email address of the account to connect; the user is asked when omitted"`
	DeviceFlow bool   `json:"device_flow,omitempty" jsonschema:"use a code typed on another device instead of opening a local browser"`
}

func (s *Server) connectAccount(ctx context.Context, req *mcp.CallToolRequest, in connectInput) (*mcp.CallToolResult, error) {
	addr := in.Email
	if addr == "" {
		r, res, err := newDialog(req).ask(ctx, "email", &mcp.ElicitParams{
			Message: "Email address of the mail account to connect (you will sign in on your mail server's page, not here)",
			RequestedSchema: &jsonschema.Schema{
				Type:       "object",
				Properties: map[string]*jsonschema.Schema{"email": {Type: "string", Format: "email", Title: "Email address"}},
				Required:   []string{"email"},
			},
		})
		if errors.Is(err, errNoElicitation) {
			return nil, errors.New(`ask the user for their email address and call connect_account again with "email"`)
		}
		if err != nil || res != nil {
			return res, err
		}
		if r.Action != "accept" {
			return nil, errors.New("the user cancelled")
		}
		addr, _ = r.Content["email"].(string)
	}
	if _, err := jmapc.Domain(addr); err != nil {
		return nil, err
	}
	msg, err := s.opts.Connector.Connect(ctx, addr, in.DeviceFlow)
	if err != nil {
		return nil, err
	}
	return message("%s", msg), nil
}

func (s *Server) registerIdentities() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "list_identities",
		Description: "List the sender identities (From addresses) available for drafting and sending.",
		Annotations: readOnly("List identities"),
	}, handler(s.listIdentities))
}

type listIdentitiesInput struct {
	Account string `json:"account,omitempty" jsonschema:"email address of the connected account to use; defaults to the default account"`
}

func (m *mailContext) identities(ctx context.Context) ([]*identity.Identity, error) {
	if !m.c.HasCapability(ctx, jmapc.CapSubmission) {
		return nil, nil
	}
	r := &jmap.Request{}
	id := r.Invoke(&identity.Get{Account: m.id})
	resp, err := m.c.Do(ctx, r)
	if err != nil {
		return nil, err
	}
	g, err := jmapc.Result[*identity.GetResponse](resp, id)
	if err != nil {
		return nil, err
	}
	return g.List, nil
}

func (s *Server) listIdentities(ctx context.Context, req *mcp.CallToolRequest, in listIdentitiesInput) (*mcp.CallToolResult, error) {
	m, res, err := s.mail(ctx, newDialog(req), in.Account)
	if err != nil || res != nil {
		return res, err
	}
	ids, err := m.identities(ctx)
	if err != nil {
		return nil, err
	}
	type view struct {
		ID      string   `json:"id"`
		Name    string   `json:"name,omitempty"`
		Email   string   `json:"email"`
		ReplyTo []string `json:"reply_to,omitempty"`
	}
	out := make([]view, 0, len(ids))
	for _, i := range ids {
		out = append(out, view{ID: string(i.ID), Name: i.Name, Email: i.Email, ReplyTo: mailview.Addresses(i.ReplyTo)})
	}
	return text(map[string]any{"account": m.acct.Email, "identities": out}), nil
}

func (s *Server) registerStatus() {
	s.AddResource(&mcp.Resource{
		URI:         "jmap-mcp://status",
		Name:        "status",
		Title:       "Connection status",
		Description: "Connected accounts, discovered JMAP servers and the capabilities they announce. Useful for debugging.",
		MIMEType:    "application/json",
	}, s.status)
}

func (s *Server) status(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	accts, err := s.opts.Backend.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	type acctView struct {
		Email        string   `json:"email"`
		Default      bool     `json:"default,omitempty"`
		SessionURL   string   `json:"session_url"`
		APIURL       string   `json:"api_url,omitempty"`
		Username     string   `json:"username,omitempty"`
		Capabilities []string `json:"capabilities,omitempty"`
		Error        string   `json:"error,omitempty"`
	}
	views := make([]acctView, 0, len(accts))
	for _, a := range accts {
		v := acctView{Email: a.Email, Default: a.Default, SessionURL: a.Client.SessionURL}
		if sess, err := a.Client.Session(ctx); err != nil {
			v.Error = err.Error()
		} else {
			v.APIURL, v.Username = sess.APIURL, sess.Username
			for c := range sess.Capabilities {
				v.Capabilities = append(v.Capabilities, string(c))
			}
			sort.Strings(v.Capabilities)
		}
		views = append(views, v)
	}
	b, err := json.MarshalIndent(map[string]any{
		"server": "jmap-mcp", "version": s.opts.Version, "mode": s.opts.Mode, "send_enabled": s.opts.SendEnabled, "accounts": views,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "application/json", Text: string(b)}}}, nil
}
