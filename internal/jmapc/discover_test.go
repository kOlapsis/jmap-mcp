package jmapc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

type fakeResolver map[string][]*net.SRV

func (f fakeResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if srvs, ok := f["_"+service+"._"+proto+"."+name]; ok {
		return "", srvs, nil
	}
	return "", nil, errors.New("no such host")
}

func jmapServer(t *testing.T) (*httptest.Server, *http.Client) {
	mux := http.NewServeMux()
	mux.Handle("/.well-known/jmap", http.RedirectHandler("/jmap/session", http.StatusTemporaryRedirect))
	mux.HandleFunc("/jmap/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="test"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"capabilities":{"urn:ietf:params:jmap:core":{},"urn:ietf:params:jmap:mail":{},"x:unknown":{"weird":[1,"a"]}},
			"accounts":{"A1":{"name":"alice@example.com","isPersonal":true,"accountCapabilities":{"urn:ietf:params:jmap:mail":{"maxMailboxesPerEmail":null}}}},
			"primaryAccounts":{"urn:ietf:params:jmap:mail":"A1"},"username":"alice@example.com",
			"apiUrl":"/jmap/","downloadUrl":"/jmap/download/{accountId}/{blobId}/{name}?accept={type}","uploadUrl":"/jmap/upload/{accountId}/","state":"s1"}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	hc := netguard.Options{AllowPrivate: true, InsecureTLS: true, Resolve: map[string]string{
		"jmap.example.com:8443": u.Host, "example.com:443": u.Host, "example.org:443": "127.0.0.1:1",
	}}.Client(5 * time.Second)
	return srv, hc
}

func TestDiscoverSessionSRV(t *testing.T) {
	_, hc := jmapServer(t)
	r := fakeResolver{"_jmap._tcp.example.com": {{Target: "jmap.example.com.", Port: 8443}}}
	got, err := DiscoverSession(context.Background(), hc, r, "Alice <alice@Example.COM>")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://jmap.example.com:8443/jmap/session" {
		t.Fatalf("session URL = %s", got)
	}
}

func TestDiscoverSessionFallbackToDomain(t *testing.T) {
	_, hc := jmapServer(t)
	got, err := DiscoverSession(context.Background(), hc, fakeResolver{}, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/jmap/session" {
		t.Fatalf("session URL = %s", got)
	}
	if _, err := DiscoverSession(context.Background(), hc, fakeResolver{}, "bob@example.org"); err == nil {
		t.Fatal("expected an error for a domain without JMAP")
	}
}

func TestDomain(t *testing.T) {
	for _, bad := range []string{"nope", "a@b", "a@exa mple.com", "a@[127.0.0.1]", "a@ex/ample.com"} {
		if _, err := Domain(bad); err == nil {
			t.Errorf("Domain(%q) accepted", bad)
		}
	}
}

func TestSessionToleratesUnknownCapabilities(t *testing.T) {
	srv, hc := jmapServer(t)
	base := hc.Transport
	hc.Transport = roundTripper(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("Authorization", "Bearer x")
		return base.RoundTrip(r)
	})
	c := &Client{HTTP: hc, SessionURL: srv.URL + "/jmap/session"}
	s, err := c.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.APIURL != srv.URL+"/jmap/" || !strings.Contains(s.DownloadURL, "{blobId}") {
		t.Fatalf("relative URLs not resolved: %+v", s)
	}
	if id, _ := c.MailAccount(context.Background()); id != "A1" || !c.HasCapability(context.Background(), CapMail) || c.HasCapability(context.Background(), CapSieve) {
		t.Fatalf("account %s", id)
	}
}

func TestHTTPErrors(t *testing.T) {
	for status, want := range map[int]string{401: ErrUnauthorized.Error(), 429: "HTTP 429 urn:ietf:params:jmap:error:limit: too many"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:jmap:error:limit","detail":"too many"}`))
		}))
		c := &Client{HTTP: srv.Client(), SessionURL: srv.URL}
		_, err := c.Session(context.Background())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("status %s: %v", strconv.Itoa(status), err)
		}
		srv.Close()
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
