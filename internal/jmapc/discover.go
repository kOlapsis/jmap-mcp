package jmapc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
)

// Resolver looks up SRV records; *net.Resolver implements it.
type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// Domain returns the lower-cased domain of an email address.
func Domain(address string) (string, error) {
	a, err := mail.ParseAddress(address)
	if err != nil {
		return "", fmt.Errorf("invalid email address: %w", err)
	}
	at := strings.LastIndexByte(a.Address, '@')
	d := strings.ToLower(strings.TrimSuffix(a.Address[at+1:], "."))
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return "", fmt.Errorf("invalid email domain %q", d)
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return "", fmt.Errorf("invalid email domain %q", d)
		}
	}
	return d, nil
}

// DiscoverSession finds the JMAP session URL for an email address (RFC 8620 §2.2).
func DiscoverSession(ctx context.Context, hc *http.Client, r Resolver, address string) (string, error) {
	domain, err := Domain(address)
	if err != nil {
		return "", err
	}
	var candidates []string
	if _, srvs, err := r.LookupSRV(ctx, "jmap", "tcp", domain); err == nil {
		for _, s := range srvs {
			target := strings.ToLower(strings.TrimSuffix(s.Target, "."))
			if target == "" {
				continue
			}
			if s.Port != 443 {
				target = net.JoinHostPort(target, strconv.Itoa(int(s.Port)))
			}
			candidates = append(candidates, "https://"+target+"/.well-known/jmap")
		}
	}
	candidates = append(candidates, "https://"+domain+"/.well-known/jmap")
	var errs []error
	for _, c := range candidates {
		u, err := probeSession(ctx, hc, c)
		if err == nil {
			return u, nil
		}
		errs = append(errs, err)
	}
	return "", fmt.Errorf("no JMAP server found for %s: %w", domain, errors.Join(errs...))
}

// probeSession follows the well-known redirect chain; the unauthenticated end of it is the session resource.
func probeSession(ctx context.Context, hc *http.Client, wellKnown string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return resp.Request.URL.String(), nil
	case http.StatusOK:
		var s struct {
			APIURL string `json:"apiUrl"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s) == nil && s.APIURL != "" {
			return resp.Request.URL.String(), nil
		}
	}
	return "", fmt.Errorf("%s: unexpected HTTP %d", wellKnown, resp.StatusCode)
}
