package mailauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

func idToken(claims map[string]any) *oauth2.Token {
	b, _ := json.Marshal(claims)
	raw := "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
	return (&oauth2.Token{AccessToken: "a"}).WithExtra(map[string]any{"id_token": raw})
}

func TestIDTokenSubject(t *testing.T) {
	m := &Meta{}
	m.Issuer = "https://mail.example.com"
	cfg := &oauth2.Config{ClientID: "client", Scopes: []string{"openid"}}
	good := map[string]any{"iss": "https://mail.example.com", "aud": "client", "nonce": "n1", "sub": "42"}
	if sub, err := IDTokenSubject(m, idToken(good), cfg, "n1"); err != nil || sub != "42" {
		t.Fatalf("%q %v", sub, err)
	}
	if _, err := IDTokenSubject(m, &oauth2.Token{AccessToken: "a"}, cfg, "n1"); err == nil {
		t.Fatal("openid was requested: an id_token is required")
	}
	if sub, err := IDTokenSubject(m, &oauth2.Token{AccessToken: "a"}, &oauth2.Config{ClientID: "client"}, "n1"); err != nil || sub != "" {
		t.Fatal("without openid, no id_token is fine")
	}
	for name, claims := range map[string]map[string]any{
		"nonce":    {"iss": "https://mail.example.com", "aud": "client", "nonce": "other", "sub": "42"},
		"issuer":   {"iss": "https://evil.example", "aud": "client", "nonce": "n1", "sub": "42"},
		"audience": {"iss": "https://mail.example.com", "aud": []string{"someone"}, "nonce": "n1", "sub": "42"},
		"subject":  {"iss": "https://mail.example.com", "aud": "client", "nonce": "n1"},
	} {
		if _, err := IDTokenSubject(m, idToken(claims), cfg, "n1"); err == nil {
			t.Errorf("%s mismatch accepted", name)
		}
	}
}

func TestScopesAndIssuer(t *testing.T) {
	m := &Meta{}
	m.ScopesSupported = []string{"openid", MailScope, "offline_access", "other"}
	if s := strings.Join(Scopes(m), " "); s != "openid "+MailScope+" offline_access" {
		t.Fatalf("scopes %s", s)
	}
	m.ScopesSupported = []string{"openid", "email", "profile", "offline_access"}
	if s := strings.Join(Scopes(m), " "); s != "openid email offline_access" {
		t.Fatalf("OpenID provider scopes %s", s)
	}
	if CheckIssuer(m, "") != nil {
		t.Fatal("iss is optional when not advertised")
	}
	m.Issuer, m.AuthorizationResponseIssParameterSupported = "https://a", true
	if CheckIssuer(m, "") == nil || CheckIssuer(m, "https://b") == nil || CheckIssuer(m, "https://a/") != nil {
		t.Fatal("iss checks")
	}
}

func TestSameSite(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"example.com", "mail.example.com", true},
		{"jmap.example.co.uk", "auth.example.co.uk", true},
		{"example.com", "example.net", false},
		{"evil.com", "mail.example.com", false},
		{"a.github.io", "b.github.io", false},
		{"Mail.Example.com.", "mail.example.com", true},
	} {
		if got := SameSite(c.a, c.b); got != c.want {
			t.Errorf("SameSite(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

type noSRV struct{}

func (noSRV) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, fmt.Errorf("no such host")
}

// A JMAP host naming another domain's authorization server must be refused, or it would receive that server's tokens.
func TestDiscoverRefusesForeignAuthorizationServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.Split(r.Host, ":")[0]
		switch {
		case r.URL.Path == "/.well-known/jmap":
			http.Redirect(w, r, "/jmap/session", http.StatusTemporaryRedirect)
		case r.URL.Path == "/jmap/session":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": "https://" + host, "authorization_servers": []string{"https://idp.example.com"}})
		case r.URL.Path == "/.well-known/oauth-authorization-server" && host == "idp.example.com":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://idp.example.com", "authorization_endpoint": "https://idp.example.com/a",
				"token_endpoint": "https://idp.example.com/t", "code_challenge_methods_supported": []string{"S256"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	n := netguard.Options{AllowPrivate: true, InsecureTLS: true, Resolve: map[string]string{
		"evil.org:443": u.Host, "idp.example.com:443": u.Host, "example.com:443": u.Host,
	}}
	e := NewEnv(n)
	e.Resolver = jmapc.Resolver(noSRV{})
	if _, err := e.Discover(context.Background(), "victim@evil.org"); err == nil || !strings.Contains(err.Error(), "not under the same domain") {
		t.Fatalf("foreign authorization server accepted: %v", err)
	}
	s, err := e.Discover(context.Background(), "alice@example.com")
	if err != nil || s.Meta.Issuer != "https://idp.example.com" {
		t.Fatalf("same-domain authorization server refused: %v", err)
	}
}

func TestRotatedRefreshTokenIsSaved(t *testing.T) {
	var mu sync.Mutex
	valid, n := "rt0", 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/token" {
			if r.PostFormValue("refresh_token") != valid {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			n++
			valid = fmt.Sprintf("rt%d", n)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","expires_in":1,"refresh_token":%q}`, valid)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"capabilities":{},"accounts":{},"primaryAccounts":{},"username":"a","apiUrl":"https://mail.example.com/api","state":"s"}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	e := NewEnv(netguard.Options{AllowPrivate: true, InsecureTLS: true, Resolve: map[string]string{"mail.example.com:443": u.Host}})
	cfg := &oauth2.Config{ClientID: "c", Endpoint: oauth2.Endpoint{TokenURL: "https://mail.example.com/token", AuthStyle: oauth2.AuthStyleInParams}}
	var saved []string
	c := e.Client(cfg, &oauth2.Token{AccessToken: "at", RefreshToken: "rt0", Expiry: time.Now().Add(-time.Minute)}, "https://mail.example.com/session", func(t *oauth2.Token) {
		saved = append(saved, t.RefreshToken)
	})
	for range 2 {
		c.Invalidate()
		if _, err := c.Session(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(saved, " ") != "rt1 rt2" {
		t.Fatalf("saved refresh tokens %v", saved)
	}
}

func TestBearerNotSentAcrossHosts(t *testing.T) {
	var got = map[string]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.Split(r.Host, ":")[0]
		got[host+r.URL.Path] = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, "https://cdn.example.net/blob", http.StatusFound)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	n := netguard.Options{AllowPrivate: true, InsecureTLS: true, Resolve: map[string]string{"mail.example.com:443": u.Host, "cdn.example.net:443": u.Host}}
	hc := n.Client(5 * time.Second)
	hc.Transport = &BearerTransport{Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "secret"}), Base: hc.Transport}
	for _, p := range []string{"/same", "/cross"} {
		resp, err := hc.Get("https://mail.example.com" + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if got["mail.example.com/final"] != "Bearer secret" || got["mail.example.com/cross"] != "Bearer secret" {
		t.Fatalf("token missing on the mail host: %v", got)
	}
	if got["cdn.example.net/blob"] != "" {
		t.Fatal("token leaked to another host after a redirect")
	}
}
