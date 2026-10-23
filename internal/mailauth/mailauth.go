// Package mailauth is the OAuth client of the mail server: discovery, registration and tokens.
package mailauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

// MailScope is the JMAP mail scope advertised by Stalwart and other JMAP servers.
const MailScope = "urn:ietf:params:oauth:scope:mail"

// Meta is RFC 8414 metadata plus the device endpoint (RFC 8628).
type Meta struct {
	oauthex.AuthServerMeta
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`
}

// Server is a discovered mail server.
type Server struct {
	SessionURL string
	Meta       *Meta
}

// Registration is this program's client registration at one authorization server.
type Registration struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	AuthMethod   string   `json:"auth_method"`
	RedirectURIs []string `json:"redirect_uris"`
	Static       bool     `json:"static,omitempty"`
}

// Env bundles the guarded HTTP client used for every request to mail servers.
type Env struct {
	HTTP     *http.Client
	Net      netguard.Options
	Resolver jmapc.Resolver
}

// NewEnv returns an Env enforcing the network policy.
func NewEnv(n netguard.Options) *Env {
	return &Env{HTTP: n.Client(30 * time.Second), Net: n, Resolver: net.DefaultResolver}
}

// Context carries the guarded HTTP client for golang.org/x/oauth2.
func (e *Env) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, e.HTTP)
}

// Discover finds the JMAP session and the authorization server for an email address.
func (e *Env) Discover(ctx context.Context, email string) (*Server, error) {
	sessionURL, err := jmapc.DiscoverSession(ctx, e.HTTP, e.Resolver, email)
	if err != nil {
		return nil, err
	}
	meta, err := e.DiscoverAuthServer(ctx, sessionURL)
	if err != nil {
		return nil, err
	}
	return &Server{SessionURL: sessionURL, Meta: meta}, nil
}

// DiscoverAuthServer finds the authorization server protecting a session URL:
// RFC 9728 resource metadata first, then RFC 8414 and OpenID discovery on the same origin.
func (e *Env) DiscoverAuthServer(ctx context.Context, sessionURL string) (*Meta, error) {
	var issuers []string
	if iss, err := e.protectedResourceIssuer(ctx, sessionURL); err == nil && iss != "" {
		issuers = append(issuers, iss)
	}
	u, err := url.Parse(sessionURL)
	if err != nil {
		return nil, err
	}
	if origin := u.Scheme + "://" + u.Host; !slices.Contains(issuers, origin) {
		issuers = append(issuers, origin)
	}
	var errs []error
	for _, iss := range issuers {
		m, err := e.authServerMeta(ctx, iss)
		if err == nil {
			return m, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("no OAuth authorization server found for %s: %w", u.Host, errors.Join(errs...))
}

func (e *Env) protectedResourceIssuer(ctx context.Context, sessionURL string) (string, error) {
	su, err := url.Parse(sessionURL)
	if err != nil {
		return "", err
	}
	var metaURLs []string
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sessionURL, nil)
	if err != nil {
		return "", err
	}
	if resp, err := e.HTTP.Do(req); err == nil {
		resp.Body.Close()
		if challenges, err := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate")); err == nil {
			for _, c := range challenges {
				if ref := c.Params["resource_metadata"]; ref != "" {
					if mu, err := resp.Request.URL.Parse(ref); err == nil {
						metaURLs = append(metaURLs, mu.String())
					}
				}
			}
		}
	}
	metaURLs = append(metaURLs, su.Scheme+"://"+su.Host+"/.well-known/oauth-protected-resource")
	for _, mu := range metaURLs {
		var prm oauthex.ProtectedResourceMetadata
		if e.getJSON(ctx, mu, &prm) == nil && len(prm.AuthorizationServers) > 0 {
			return prm.AuthorizationServers[0], nil
		}
	}
	return "", nil
}

func (e *Env) authServerMeta(ctx context.Context, issuer string) (*Meta, error) {
	iu, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	path := strings.TrimSuffix(iu.Path, "/")
	candidates := []string{
		iu.Scheme + "://" + iu.Host + "/.well-known/oauth-authorization-server" + path,
		iu.Scheme + "://" + iu.Host + path + "/.well-known/openid-configuration",
	}
	var errs []error
	for _, c := range candidates {
		m := &Meta{}
		if err := e.getJSON(ctx, c, m); err != nil {
			errs = append(errs, err)
			continue
		}
		if strings.TrimSuffix(m.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
			errs = append(errs, fmt.Errorf("%s: issuer %q does not match %q", c, m.Issuer, issuer))
			continue
		}
		if !slices.Contains(m.CodeChallengeMethodsSupported, "S256") {
			errs = append(errs, fmt.Errorf("%s: PKCE S256 is not supported", issuer))
			continue
		}
		for _, ep := range []string{m.AuthorizationEndpoint, m.TokenEndpoint} {
			if err := e.Net.CheckURL(ep); err != nil {
				return nil, err
			}
		}
		for _, ep := range []string{m.RegistrationEndpoint, m.DeviceAuthorizationEndpoint} {
			if ep != "" {
				if err := e.Net.CheckURL(ep); err != nil {
					return nil, err
				}
			}
		}
		return m, nil
	}
	return nil, errors.Join(errs...)
}

func (e *Env) getJSON(ctx context.Context, u string, out any) error {
	if err := e.Net.CheckURL(u); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// Register registers a client dynamically (RFC 7591). A confidential registration
// falls back to a public PKCE client when the server only allows anonymous public clients.
func (e *Env) Register(ctx context.Context, m *Meta, name string, redirectURIs []string, confidential bool) (*Registration, error) {
	if m.RegistrationEndpoint == "" {
		return nil, errors.New("the mail server does not support dynamic client registration")
	}
	grants := []string{"authorization_code", "refresh_token"}
	if m.DeviceAuthorizationEndpoint != "" && !confidential {
		grants = append(grants, "urn:ietf:params:oauth:grant-type:device_code")
	}
	methods := []string{"none"}
	if confidential {
		methods = []string{"client_secret_basic", "client_secret_post", "none"}
	}
	var errs []error
	for _, method := range methods {
		if len(m.TokenEndpointAuthMethodsSupported) > 0 && !slices.Contains(m.TokenEndpointAuthMethodsSupported, method) {
			continue
		}
		resp, err := oauthex.RegisterClient(ctx, m.RegistrationEndpoint, &oauthex.ClientRegistrationMetadata{
			RedirectURIs:            redirectURIs,
			TokenEndpointAuthMethod: method,
			GrantTypes:              grants,
			ResponseTypes:           []string{"code"},
			ClientName:              name,
			ClientURI:               "https://github.com/kOlapsis/jmap-mcp",
			Scope:                   strings.Join(Scopes(m), " "),
		}, e.HTTP)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", method, err))
			continue
		}
		if method != "none" && resp.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("%s: no client secret issued", method))
			continue
		}
		return &Registration{ClientID: resp.ClientID, ClientSecret: resp.ClientSecret, AuthMethod: method, RedirectURIs: redirectURIs}, nil
	}
	return nil, fmt.Errorf("dynamic client registration refused: %w", errors.Join(errs...))
}

// Scopes returns the scopes to request: the JMAP mail scope and offline_access when advertised.
func Scopes(m *Meta) []string {
	var s []string
	for _, want := range []string{MailScope, "offline_access"} {
		if slices.Contains(m.ScopesSupported, want) {
			s = append(s, want)
		}
	}
	return s
}

// Config builds the oauth2 configuration for a registration.
func Config(m *Meta, r *Registration, redirectURL string) *oauth2.Config {
	style := oauth2.AuthStyleInParams
	if r.AuthMethod == "client_secret_basic" {
		style = oauth2.AuthStyleInHeader
	}
	return &oauth2.Config{
		ClientID:     r.ClientID,
		ClientSecret: r.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       Scopes(m),
		Endpoint: oauth2.Endpoint{
			AuthURL:       m.AuthorizationEndpoint,
			TokenURL:      m.TokenEndpoint,
			DeviceAuthURL: m.DeviceAuthorizationEndpoint,
			AuthStyle:     style,
		},
	}
}

// CheckIssuer validates the RFC 9207 iss parameter of an authorization response.
func CheckIssuer(m *Meta, iss string) error {
	if iss == "" {
		if m.AuthorizationResponseIssParameterSupported {
			return errors.New("missing iss parameter in the authorization response")
		}
		return nil
	}
	if strings.TrimSuffix(iss, "/") != strings.TrimSuffix(m.Issuer, "/") {
		return fmt.Errorf("unexpected issuer %q in the authorization response", iss)
	}
	return nil
}

// Client returns a JMAP client whose token refreshes transparently; save is called with every new token.
func (e *Env) Client(cfg *oauth2.Config, tok *oauth2.Token, sessionURL string, save func(*oauth2.Token)) *jmapc.Client {
	src := &savingSource{src: cfg.TokenSource(e.Context(context.Background()), tok), last: tok.AccessToken, save: save}
	return &jmapc.Client{
		HTTP:       &http.Client{Timeout: e.HTTP.Timeout, CheckRedirect: e.HTTP.CheckRedirect, Transport: &oauth2.Transport{Source: src, Base: e.HTTP.Transport}},
		SessionURL: sessionURL,
	}
}

type savingSource struct {
	src  oauth2.TokenSource
	save func(*oauth2.Token)

	mu   sync.Mutex
	last string
}

func (s *savingSource) Token() (*oauth2.Token, error) {
	t, err := s.src.Token()
	if err != nil {
		return nil, fmt.Errorf("%w (%w)", jmapc.ErrUnauthorized, err)
	}
	s.mu.Lock()
	changed := t.AccessToken != s.last
	s.last = t.AccessToken
	s.mu.Unlock()
	if changed && s.save != nil {
		s.save(t)
	}
	return t, nil
}
