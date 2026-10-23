package httpd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
	"github.com/kOlapsis/jmap-mcp/internal/netguard"
	"github.com/kOlapsis/jmap-mcp/internal/store"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

const clientRedirect = "http://127.0.0.1:9999/cb"

type bridge struct {
	srv  *Server
	http *httptest.Server
	net  netguard.Options
}

func newBridge(t *testing.T, resolve map[string]string) *bridge {
	t.Helper()
	n := netguard.Options{AllowPrivate: true, InsecureTLS: true, AllowHTTP: true, Resolve: resolve}
	srv, err := New(&config.Config{DataDir: t.TempDir(), Net: n}, "test", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &bridge{srv: srv, http: hs, net: n}
}

func mailResolve(m *fakeMail) map[string]string {
	u, _ := url.Parse(m.URL)
	return map[string]string{"example.com:443": u.Host}
}

var requestField = regexp.MustCompile(`name="request" value="([^"]+)"`)

// authorize plays the user's browser from an authorization URL of the bridge to the client redirect.
// login, when set, stands in for the mail server's own sign-in page and returns the URL it would redirect to.
func (b *bridge) authorize(authURL, email string) (url.Values, error) {
	return b.authorizeWith(authURL, email, nil)
}

func (b *bridge) authorizeWith(authURL, email string, login func(string) (string, error)) (url.Values, error) {
	jar, _ := cookiejar.New(nil)
	hc := b.net.Client(10 * time.Second)
	hc.Jar = jar
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(authURL)
	if err != nil {
		return nil, err
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "" {
		u, _ := url.Parse(loc)
		return u.Query(), nil
	}
	m := requestField.FindSubmatch(page)
	if m == nil {
		return nil, fmt.Errorf("no consent form (HTTP %d): %s", resp.StatusCode, page)
	}
	resp, err = hc.PostForm(b.http.URL+"/authorize", url.Values{"request": {string(m[1])}, "email": {email}, "action": {"allow"}})
	for hops := 0; err == nil && hops < 10; hops++ {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, clientRedirect) {
			u, _ := url.Parse(loc)
			return u.Query(), nil
		}
		if loc == "" {
			return nil, fmt.Errorf("ended at HTTP %d: %s", resp.StatusCode, body)
		}
		if login != nil && !strings.HasPrefix(loc, b.http.URL) {
			if loc, err = login(loc); err != nil {
				return nil, err
			}
		}
		resp, err = hc.Get(loc)
	}
	return nil, fmt.Errorf("authorization did not complete: %w", err)
}

func TestEndToEndWithSDKClient(t *testing.T) {
	mail := newFakeMail(t)
	b := newBridge(t, mailResolve(mail))
	ctx := context.Background()
	h, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{clientRedirect}, ClientName: "e2e client", TokenEndpointAuthMethod: "none",
			GrantTypes: []string{"authorization_code", "refresh_token"},
		}},
		RedirectURL:         clientRedirect,
		RequestRefreshToken: true,
		AuthorizationCodeFetcher: func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			q, err := b.authorize(args.URL, "Alice@example.com")
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
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_mailboxes", Arguments: map[string]any{}})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `"path":"Inbox"`) {
		t.Fatalf("list_mailboxes: %v %+v", err, res)
	}
	res, _ = cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_accounts", Arguments: map[string]any{}})
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "alice@example.com") {
		t.Fatalf("list_accounts: %s", txt)
	}
	tl, _ := cs.ListTools(ctx, nil)
	for _, tool := range tl.Tools {
		if tool.Name == "connect_account" || tool.Name == "send_email" {
			t.Errorf("%s must not be exposed in HTTP mode with sending disabled", tool.Name)
		}
	}
}

// oauthClient is a hand-written client used to probe the authorization server.
type oauthClient struct {
	b        *bridge
	id       string
	verifier string
}

func (c *oauthClient) authURL(extra url.Values) string {
	verifier, challenge := pkce()
	c.verifier = verifier
	q := url.Values{"response_type": {"code"}, "client_id": {c.id}, "redirect_uri": {clientRedirect}, "state": {"xyz"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {c.b.http.URL + "/mcp"}}
	for k, v := range extra {
		q[k] = v
	}
	return c.b.http.URL + "/authorize?" + q.Encode()
}

func (c *oauthClient) token(form url.Values) (int, map[string]any) {
	form.Set("client_id", c.id)
	resp, err := http.PostForm(c.b.http.URL+"/token", form)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func pkce() (string, string) {
	v := store.RandomToken("")
	return v, s256(v)
}

func (c *oauthClient) login(t *testing.T) map[string]any {
	t.Helper()
	q, err := c.b.authorize(c.authURL(nil), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("state") != "xyz" || q.Get("iss") != c.b.http.URL || q.Get("code") == "" {
		t.Fatalf("authorization response: %v", q)
	}
	status, tok := c.token(url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {clientRedirect}, "code_verifier": {c.verifier}})
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tok)
	}
	return tok
}

func register(t *testing.T, b *bridge, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(b.http.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func mcpStatus(t *testing.T, b *bridge, token string, header http.Header) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.http.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if h := header.Get("Host"); h != "" {
		req.Host = h
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

func TestAuthorizationServer(t *testing.T) {
	mail := newFakeMail(t)
	b := newBridge(t, mailResolve(mail))

	status, www := mcpStatus(t, b, "", nil)
	if status != http.StatusUnauthorized || !strings.Contains(www, `resource_metadata="`+b.http.URL+`/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("unauthenticated MCP request: %d %q", status, www)
	}
	var prm oauthex.ProtectedResourceMetadata
	resp, _ := http.Get(b.http.URL + "/.well-known/oauth-protected-resource/mcp")
	_ = json.NewDecoder(resp.Body).Decode(&prm)
	resp.Body.Close()
	if prm.Resource != b.http.URL+"/mcp" || prm.AuthorizationServers[0] != b.http.URL {
		t.Fatalf("resource metadata: %+v", prm)
	}

	if status, _ := register(t, b, `{"redirect_uris":["http://evil.example/cb"]}`); status != http.StatusBadRequest {
		t.Fatalf("http redirect accepted: %d", status)
	}
	if status, _ := register(t, b, `{"redirect_uris":["https://ok.example/cb#frag"]}`); status != http.StatusBadRequest {
		t.Fatalf("fragment accepted: %d", status)
	}
	status, reg := register(t, b, `{"redirect_uris":["`+clientRedirect+`"],"token_endpoint_auth_method":"none","client_name":"probe"}`)
	if status != http.StatusCreated || reg["client_secret"] != nil {
		t.Fatalf("registration: %d %v", status, reg)
	}
	c := &oauthClient{b: b, id: reg["client_id"].(string)}

	resp, _ = http.Get(c.authURL(url.Values{"redirect_uri": {"http://127.0.0.1:9999/other"}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered redirect: %d", resp.StatusCode)
	}
	q, _ := b.authorize(c.authURL(url.Values{"code_challenge_method": {"plain"}}), "alice@example.com")
	if q.Get("error") != "invalid_request" {
		t.Fatalf("plain PKCE: %v", q)
	}
	q, _ = b.authorize(c.authURL(url.Values{"resource": {"https://other.example/mcp"}}), "alice@example.com")
	if q.Get("error") != "invalid_target" {
		t.Fatalf("foreign resource: %v", q)
	}

	q, err := b.authorize(c.authURL(nil), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if status, tok := c.token(url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {clientRedirect}, "code_verifier": {"wrong"}}); status != http.StatusBadRequest || tok["error"] != "invalid_grant" {
		t.Fatalf("bad verifier: %d %v", status, tok)
	}
	if status, _ := c.token(url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {clientRedirect}, "code_verifier": {c.verifier}}); status != http.StatusBadRequest {
		t.Fatal("a code must work only once")
	}

	tok := c.login(t)
	access := tok["access_token"].(string)
	if status, _ := mcpStatus(t, b, access, nil); status != http.StatusOK {
		t.Fatalf("authorized MCP request: %d", status)
	}
	if status, _ := mcpStatus(t, b, access, http.Header{"X-Forwarded-Host": {"other.example"}}); status != http.StatusUnauthorized {
		t.Fatalf("token accepted for another resource: %d", status)
	}
	if status, _ := mcpStatus(t, b, "jmcp_at_forged", nil); status != http.StatusUnauthorized {
		t.Fatalf("forged token accepted: %d", status)
	}
	b.srv.cfg.PublicURL = b.http.URL
	if status, _ := mcpStatus(t, b, access, http.Header{"Host": {"mcp.example.com"}}); status != http.StatusOK {
		t.Fatalf("request from a local reverse proxy with a public Host: %d", status)
	}
	b.srv.cfg.PublicURL = ""

	status, rotated := c.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}})
	if status != http.StatusOK || rotated["refresh_token"] == tok["refresh_token"] {
		t.Fatalf("refresh: %d %v", status, rotated)
	}
	if status, _ := c.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}}); status != http.StatusBadRequest {
		t.Fatal("a rotated refresh token must not work again")
	}
	if status, _ := c.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rotated["refresh_token"].(string)}}); status != http.StatusBadRequest {
		t.Fatal("reusing a rotated refresh token must revoke the whole family")
	}
	if status, _ := mcpStatus(t, b, rotated["access_token"].(string), nil); status != http.StatusUnauthorized {
		t.Fatal("access tokens of a revoked family must stop working")
	}
}

func TestClientIDMetadataDocument(t *testing.T) {
	mail := newFakeMail(t)
	const id = "https://client.example/oauth/metadata.json"
	doc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": id, "client_name": "Metadata Client", "redirect_uris": []string{clientRedirect}, "token_endpoint_auth_method": "none"})
	}))
	defer doc.Close()
	resolve := mailResolve(mail)
	du, _ := url.Parse(doc.URL)
	resolve["client.example:443"] = du.Host
	b := newBridge(t, resolve)
	c := &oauthClient{b: b, id: id}
	resp, err := http.Get(c.authURL(nil))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "Metadata Client") || !strings.Contains(string(page), "127.0.0.1:9999") {
		t.Fatalf("consent page: %s", page)
	}
	if tok := c.login(t); tok["access_token"] == nil {
		t.Fatal("no token for a CIMD client")
	}
}

func TestSignedAttachmentLinks(t *testing.T) {
	mail := newFakeMail(t)
	b := newBridge(t, mailResolve(mail))
	reg := func() string {
		_, r := register(t, b, `{"redirect_uris":["`+clientRedirect+`"],"token_endpoint_auth_method":"none"}`)
		return r["client_id"].(string)
	}
	(&oauthClient{b: b, id: reg()}).login(t)
	ctx := context.Background()
	userID, _ := b.srv.st.UpsertUser(ctx, mailIssuer, "alice@example.com")
	ub := &userBackend{s: b.srv, user: userID}
	accts, err := ub.Accounts(ctx)
	if err != nil || len(accts) != 1 {
		t.Fatalf("accounts: %v %d", err, len(accts))
	}
	req := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: http.Header{http.CanonicalHeaderKey(baseHeader): {b.http.URL}}}}
	link, err := ub.AttachmentLink(ctx, req, accts[0], "A", mailview.Attachment{ID: "blob1", Name: "rapport été.pdf", Type: "application/pdf"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "%PDF-1.7 fake" || resp.Header.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("download: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	other := &userBackend{s: b.srv, user: "someone-else"}
	forged, _ := other.AttachmentLink(ctx, req, &tools.Account{Email: "alice@example.com"}, "A", mailview.Attachment{ID: "blob1"})
	for _, bad := range []string{link[:len(link)-2] + "xx", forged} {
		resp, _ := http.Get(bad)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("link %s: HTTP %d", bad, resp.StatusCode)
		}
	}
}

func TestBaseFromHeaders(t *testing.T) {
	for _, c := range []struct {
		h    http.Header
		host string
		want string
	}{
		{http.Header{}, "bridge:8080", "http://bridge:8080"},
		{http.Header{"X-Forwarded-Proto": {"https"}, "X-Forwarded-Host": {"mcp.example.com"}}, "bridge:8080", "https://mcp.example.com"},
		{http.Header{"X-Forwarded-Proto": {"https, http"}, "X-Forwarded-Host": {"mcp.example.com"}, "X-Forwarded-Prefix": {"/mail/"}}, "b", "https://mcp.example.com/mail"},
		{http.Header{"X-Forwarded-Host": {`evil"><script>`}}, "bridge", "http://bridge"},
	} {
		if got := baseFromHeaders(c.h, c.host, false); got != c.want {
			t.Errorf("baseFromHeaders(%v) = %s, want %s", c.h, got, c.want)
		}
	}
}

func TestStaticClientFallback(t *testing.T) {
	mail := newFakeMail(t)
	mail.closedReg = true
	b := newBridge(t, mailResolve(mail))
	_, reg := register(t, b, `{"redirect_uris":["`+clientRedirect+`"],"token_endpoint_auth_method":"none"}`)
	c := &oauthClient{b: b, id: reg["client_id"].(string)}
	if _, err := b.authorize(c.authURL(nil), "alice@example.com"); err == nil || !strings.Contains(err.Error(), b.http.URL+"/callback") {
		t.Fatalf("expected the operator instructions with the redirect address, got %v", err)
	}

	admin := func(token string, form url.Values, header http.Header) int {
		req, _ := http.NewRequest(http.MethodPost, b.http.URL+"/admin", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range header {
			req.Header[k] = v
		}
		if token != "" {
			req.SetBasicAuth("admin", token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	form := url.Values{"server": {"alice@example.com"}, "client_id": {"static-client"}, "client_secret": {"static-secret"}, "auth_method": {"client_secret_basic"}}
	if status := admin("", form, nil); status != http.StatusUnauthorized {
		t.Fatalf("admin without token: %d", status)
	}
	if status := admin("wrong", form, nil); status != http.StatusUnauthorized {
		t.Fatalf("admin with a wrong token: %d", status)
	}
	if status := admin(b.srv.AdminToken(), form, http.Header{"Sec-Fetch-Site": {"cross-site"}}); status != http.StatusForbidden {
		t.Fatalf("cross-site admin post: %d", status)
	}
	if status := admin(b.srv.AdminToken(), form, nil); status != http.StatusOK {
		t.Fatalf("admin save: %d", status)
	}
	if tok := c.login(t); tok["access_token"] == nil {
		t.Fatal("no token with the static client")
	}
}
