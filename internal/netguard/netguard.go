// Package netguard builds HTTP clients that refuse to reach private networks.
package netguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// Options relaxes the guard. The zero value is the production policy.
type Options struct {
	AllowPrivate bool              // allow loopback, private and link-local destinations
	AllowHTTP    bool              // allow plain http:// URLs (development only)
	InsecureTLS  bool              // skip TLS verification (development only)
	Resolve      map[string]string // "host:port" -> "ip:port" overrides (development only)
}

// ErrBlocked is returned when a destination is refused by the policy.
var ErrBlocked = errors.New("destination not allowed")

const maxRedirects = 5

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// PublicAddr reports whether addr is a globally routable unicast address.
func PublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsMulticast() ||
		addr.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// CheckURL validates the scheme of an outbound URL.
func (o Options) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid URL", ErrBlocked)
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: %s", ErrBlocked, raw)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && o.AllowHTTP) {
		return nil
	}
	return fmt.Errorf("%w: only https URLs are accepted (%s)", ErrBlocked, u.Redacted())
}

// Client returns an HTTP client enforcing the policy on every connection and redirect.
func (o Options) Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !o.AllowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !PublicAddr(ap.Addr()) {
				return fmt.Errorf("%w: %s resolves to a non-public address", ErrBlocked, address)
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if to, ok := o.Resolve[addr]; ok {
				addr = to
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureTLS}, //nolint:gosec // development option
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("%w: too many redirects", ErrBlocked)
			}
			return o.CheckURL(req.URL.String())
		},
	}
}
