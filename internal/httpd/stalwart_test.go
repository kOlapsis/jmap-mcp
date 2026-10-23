//go:build integration

package httpd

import (
	"context"
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
