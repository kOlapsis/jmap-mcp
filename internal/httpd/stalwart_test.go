//go:build integration

package httpd

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/kOlapsis/jmap-mcp/internal/testenv"
)

func TestStalwartHTTPMode(t *testing.T) {
	sw := testenv.Start(t)
	alice := sw.CreateUser(t, "alice", "alice-password-1")
	sw.Seed(t, alice, "alice-password-1", testenv.Fixtures...)
	b := newBridge(t, sw.Net().Resolve)
	ctx := context.Background()
	h, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{clientRedirect}, ClientName: "Claude", TokenEndpointAuthMethod: "none",
			GrantTypes: []string{"authorization_code", "refresh_token"},
		}},
		RedirectURL: clientRedirect,
		AuthorizationCodeFetcher: func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			q, err := b.authorizeWith(args.URL, alice, func(loginURL string) (string, error) {
				return sw.Authorize(loginURL, alice, "alice-password-1")
			})
			if err != nil {
				return nil, err
			}
			return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: b.http.URL + "/mcp", OAuthHandler: h}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "search_emails", Arguments: map[string]any{"subject": "Notes"}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "Notes and picture") {
		t.Fatalf("search_emails: %v %+v", err, res)
	}
	tl, _ := cs.ListTools(ctx, nil)
	names := ""
	for _, tool := range tl.Tools {
		names += tool.Name + " "
	}
	if !strings.Contains(names, "list_identities") || !strings.Contains(names, "sieve_scripts") {
		t.Fatalf("optional tools missing in HTTP mode: %s", names)
	}
	hosts, _ := b.srv.st.StaticHosts(ctx, hostKind)
	if len(hosts) != 0 {
		t.Fatalf("dynamic registration expected, got static hosts %v", hosts)
	}
}

func TestStalwartExternalIdP(t *testing.T) {
	sw := testenv.Start(t)
	idp := testenv.StartIdP(t, "stalwart-webui", "alice@"+testenv.Domain)
	sw.UseIdP(t, idp)
	b := newBridge(t, sw.Net().Resolve)
	idp.Redirect = regexp.MustCompile("^" + regexp.QuoteMeta(b.http.URL+"/callback") + "$")
	ctx := context.Background()

	_, reg := register(t, b, `{"redirect_uris":["`+clientRedirect+`"],"token_endpoint_auth_method":"none"}`)
	c := &oauthClient{b: b, id: reg["client_id"].(string)}
	if _, err := b.authorizeWith(c.authURL(nil), idp.Email, idp.Authorize); err == nil ||
		!strings.Contains(err.Error(), idp.Issuer+" does not support dynamic client registration") || !strings.Contains(err.Error(), b.http.URL+"/callback") {
		t.Fatalf("expected the static client instructions, got %v", err)
	}
	form := url.Values{"server": {idp.Email}, "client_id": {idp.ClientID}, "auth_method": {"none"}}
	req, _ := http.NewRequest(http.MethodPost, b.http.URL+"/admin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("admin", b.srv.AdminToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("admin save: %v %v", err, resp)
	}
	resp.Body.Close()

	h, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{clientRedirect}, ClientName: "Claude", TokenEndpointAuthMethod: "none",
			GrantTypes: []string{"authorization_code", "refresh_token"},
		}},
		RedirectURL: clientRedirect,
		AuthorizationCodeFetcher: func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			q, err := b.authorizeWith(args.URL, idp.Email, idp.Authorize)
			if err != nil {
				return nil, err
			}
			return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: b.http.URL + "/mcp", OAuthHandler: h}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_accounts", Arguments: map[string]any{}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, idp.Email) {
		t.Fatalf("list_accounts: %v %+v", err, res)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_mailboxes", Arguments: map[string]any{}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `"role":"inbox"`) {
		t.Fatalf("list_mailboxes: %v %+v", err, res)
	}
	if s := idp.Scopes(); len(s) != 1 || s[0] != "openid email offline_access" {
		t.Fatalf("requested scopes %q", s)
	}
}
