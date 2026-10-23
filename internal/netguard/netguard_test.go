package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fd00::1": false, "::ffff:127.0.0.1": false,
		"224.0.0.1": false, "198.18.0.1": false,
	} {
		if got := PublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("PublicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestCheckURL(t *testing.T) {
	var o Options
	for _, u := range []string{"http://example.com/", "ftp://example.com", "https://user:pw@example.com", "javascript:alert(1)", "https:///nohost"} {
		if o.CheckURL(u) == nil {
			t.Errorf("CheckURL(%q) accepted", u)
		}
	}
	if err := o.CheckURL("https://mail.example.com/jmap"); err != nil {
		t.Error(err)
	}
	if err := (Options{AllowHTTP: true}).CheckURL("http://localhost:8080"); err != nil {
		t.Error(err)
	}
}

func TestClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := Options{AllowHTTP: true}.Client(5 * time.Second).Get(srv.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback request not blocked: %v", err)
	}
	resp, err := Options{AllowHTTP: true, AllowPrivate: true}.Client(5 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestRedirectToHTTPRefused(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()
	srv := httptest.NewTLSServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer srv.Close()
	_, err := Options{AllowPrivate: true, InsecureTLS: true}.Client(5 * time.Second).Get(srv.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("redirect to http not blocked: %v", err)
	}
}
