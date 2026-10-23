package httpd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
	"github.com/kOlapsis/jmap-mcp/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (s *Server) resource(r *http.Request) string { return s.base(r) + "/mcp" }

func (s *Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, &oauthex.ProtectedResourceMetadata{
		Resource:               s.resource(r),
		AuthorizationServers:   []string{s.base(r)},
		ScopesSupported:        []string{mcpScope},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "JMAP mail (jmap-mcp)",
	})
}

func (s *Server) authServerMetadata(w http.ResponseWriter, r *http.Request) {
	b := s.base(r)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         b,
		"authorization_endpoint":                         b + "/authorize",
		"token_endpoint":                                 b + "/token",
		"registration_endpoint":                          b + "/register",
		"revocation_endpoint":                            b + "/revoke",
		"scopes_supported":                               []string{mcpScope},
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []string{"S256"},
		"client_id_metadata_document_supported":          true,
		"service_documentation":                          "https://github.com/kOlapsis/jmap-mcp",
		"authorization_response_iss_parameter_supported": true,
	})
}

// validRedirectURI accepts https URLs, http loopback URLs and private-use schemes (RFC 8252), never fragments.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		return isLoopback(u.Hostname())
	default:
		return strings.Contains(u.Scheme, ".")
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// redirectMatches compares exactly, except that loopback redirect URIs may use any port (RFC 8252 §7.3).
func redirectMatches(registered []string, got string) bool {
	if slices.Contains(registered, got) {
		return true
	}
	g, err := url.Parse(got)
	if err != nil || g.Scheme != "http" || !isLoopback(g.Hostname()) {
		return false
	}
	for _, reg := range registered {
		r, err := url.Parse(reg)
		if err == nil && r.Scheme == "http" && r.Hostname() == g.Hostname() && r.Path == g.Path && r.RawQuery == g.RawQuery {
			return true
		}
	}
	return false
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req oauthex.ClientRegistrationMetadata
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between 1 and 10 redirect_uris are required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be https, http loopback or a private-use scheme, without fragment: "+u)
			return
		}
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type "+g)
			return
		}
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	c := &store.Client{ClientID: store.RandomToken("mcp_"), ClientName: truncate(req.ClientName, 200), RedirectURIs: req.RedirectURIs, AuthMethod: method}
	var secret string
	switch method {
	case "none":
	case "client_secret_basic", "client_secret_post":
		secret = store.RandomToken("")
		c.SecretHash = s.st.Hash(secret)
	default:
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method "+method)
		return
	}
	if err := s.st.SaveClient(r.Context(), c); err != nil {
		s.log.Error("saving client", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	resp := map[string]any{
		"client_id": c.ClientID, "client_id_issued_at": time.Now().Unix(), "client_name": c.ClientName, "redirect_uris": c.RedirectURIs,
		"token_endpoint_auth_method": method, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, resp)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type cachedClient struct {
	client  *store.Client
	expires time.Time
}

// lookupClient finds a registered client, or fetches a Client ID Metadata Document when the id is an https URL.
func (s *Server) lookupClient(ctx context.Context, id string) (*store.Client, error) {
	if !strings.HasPrefix(id, "https://") {
		return s.st.Client(ctx, id)
	}
	s.mu.Lock()
	c, ok := s.cimd[id]
	s.mu.Unlock()
	if ok && time.Now().Before(c.expires) {
		return c.client, nil
	}
	u, err := url.Parse(id)
	if err != nil || u.Path == "" || u.Path == "/" || u.Fragment != "" {
		return nil, errors.New("invalid client id URL")
	}
	if err := s.env.Net.CheckURL(id); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.env.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata document: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<10)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("client metadata document: %w", err)
	}
	if doc.ClientID != id || len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > 10 || (doc.AuthMethod != "" && doc.AuthMethod != "none") {
		return nil, errors.New("client metadata document: client_id mismatch, no redirect_uris or unsupported authentication")
	}
	for _, u := range doc.RedirectURIs {
		if !validRedirectURI(u) {
			return nil, errors.New("client metadata document: invalid redirect URI")
		}
	}
	cl := &store.Client{ClientID: id, ClientName: truncate(doc.ClientName, 200), RedirectURIs: doc.RedirectURIs, AuthMethod: "none"}
	s.mu.Lock()
	if len(s.cimd) >= 1000 {
		clear(s.cimd)
	}
	s.cimd[id] = cachedClient{client: cl, expires: time.Now().Add(10 * time.Minute)}
	s.mu.Unlock()
	return cl, nil
}

// pending is an authorization request between /authorize and /callback.
type pending struct {
	ClientID      string `json:"client_id"`
	ClientName    string `json:"client_name"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state,omitempty"`
	CodeChallenge string `json:"code_challenge"`
	Resource      string `json:"resource"`
	Scope         string `json:"scope"`
	Email         string `json:"email,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	SessionURL    string `json:"session_url,omitempty"`
	Verifier      string `json:"verifier,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	Cookie        string `json:"cookie,omitempty"`
}

// redirectError sends an OAuth error back to the client's redirect URI.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, p *pending, code, desc string) {
	u, _ := url.Parse(p.RedirectURI)
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if p.State != "" {
		q.Set("state", p.State)
	}
	q.Set("iss", s.base(r))
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.lookupClient(r.Context(), q.Get("client_id"))
	if err != nil {
		s.log.Info("unknown client", "err", err)
		s.page(w, http.StatusBadRequest, "Unknown application", "This application is not registered with the bridge.", nil)
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(client.RedirectURIs) == 1 {
		redirect = client.RedirectURIs[0]
	}
	if !redirectMatches(client.RedirectURIs, redirect) {
		s.page(w, http.StatusBadRequest, "Invalid redirect", "The redirect address does not match the application's registration.", nil)
		return
	}
	p := &pending{ClientID: client.ClientID, ClientName: client.ClientName, RedirectURI: redirect, State: q.Get("state"),
		CodeChallenge: q.Get("code_challenge"), Resource: s.resource(r), Scope: mcpScope}
	switch {
	case q.Get("response_type") != "code":
		s.redirectError(w, r, p, "unsupported_response_type", "response_type must be code")
		return
	case p.CodeChallenge == "" || q.Get("code_challenge_method") != "S256":
		s.redirectError(w, r, p, "invalid_request", "PKCE with S256 is required")
		return
	case q.Get("resource") != "" && !oauthex.MatchesResource([]string{q.Get("resource")}, p.Resource):
		s.redirectError(w, r, p, "invalid_target", "unknown resource "+q.Get("resource"))
		return
	}
	id := store.RandomToken("")
	if err := s.st.SaveAuthRequest(r.Context(), id, p, requestTTL); err != nil {
		s.log.Error("saving authorization request", "err", err)
		s.page(w, http.StatusInternalServerError, "Error", "Please retry.", nil)
		return
	}
	s.loginPage(w, id, p, "")
}

func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("request")
	p := &pending{}
	if err := s.st.AuthRequest(r.Context(), id, p, false); err != nil {
		s.page(w, http.StatusBadRequest, "Expired", "This sign-in request has expired. Start again from your assistant.", nil)
		return
	}
	if r.PostFormValue("action") != "allow" {
		_ = s.st.AuthRequest(r.Context(), id, &pending{}, true)
		s.redirectError(w, r, p, "access_denied", "the user denied access")
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	if _, err := jmapc.Domain(email); err != nil {
		s.loginPage(w, id, p, "Enter a valid email address.")
		return
	}
	srv, err := s.env.Discover(r.Context(), email)
	if err != nil {
		s.log.Info("discovery failed", "domain", domainOf(email), "err", err)
		s.loginPage(w, id, p, "No compatible mail server was found for this address (JMAP with OAuth is required).")
		return
	}
	callback := s.base(r) + "/callback"
	h, err := s.mailHost(r.Context(), srv.Meta, callback)
	if err != nil {
		s.log.Warn("mail server registration failed", "issuer", srv.Meta.Issuer, "err", err)
		s.page(w, http.StatusBadGateway, "Mail server not ready",
			"The mail server refused to register this bridge as an OAuth client. The operator of the bridge can declare a client on the mail server for the redirect address below, then enter it on the /admin page of the bridge.",
			map[string]string{"Redirect address": callback, "Authorization server": srv.Meta.Issuer})
		return
	}
	p.Email, p.Issuer, p.SessionURL, p.Verifier, p.Nonce = strings.ToLower(email), srv.Meta.Issuer, srv.SessionURL, oauth2.GenerateVerifier(), store.RandomToken("")
	p.Cookie = store.RandomToken("")
	if err := s.st.SaveAuthRequest(r.Context(), id, p, requestTTL); err != nil {
		s.page(w, http.StatusInternalServerError, "Error", "Please retry.", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: authCookie, Value: p.Cookie, Path: "/", MaxAge: int(requestTTL.Seconds()), //nolint:gosec // Secure is off only for a plain-http development URL
		HttpOnly: true, Secure: strings.HasPrefix(s.base(r), "https://"), SameSite: http.SameSiteLaxMode})
	cfg := mailauth.Config(h.Meta, h.Registration, callback)
	http.Redirect(w, r, cfg.AuthCodeURL(id, oauth2.S256ChallengeOption(p.Verifier), oauth2.SetAuthURLParam("login_hint", p.Email), oauth2.SetAuthURLParam("nonce", p.Nonce)), http.StatusFound) //nolint:gosec // the discovered mail authorization endpoint
}

const authCookie = "jmap_mcp_auth"

// s256 is the PKCE S256 transform (RFC 7636 §4.2).
func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func domainOf(email string) string {
	d, _ := jmapc.Domain(email)
	return d
}

// mailHost returns this bridge's client registration at the mail authorization server, registering it if needed.
func (s *Server) mailHost(ctx context.Context, meta *mailauth.Meta, callback string) (*store.Host, error) {
	h, err := s.st.Host(ctx, meta.Issuer, hostKind)
	if err == nil && (h.Registration.Static || slices.Contains(h.Registration.RedirectURIs, callback)) {
		if !h.Registration.Static && !reflect.DeepEqual(h.Meta, meta) {
			h.Meta = meta
			if err := s.st.SaveHost(ctx, meta.Issuer, hostKind, h); err != nil {
				return nil, err
			}
		}
		return h, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	reg, err := s.env.Register(ctx, meta, "jmap-mcp bridge", []string{callback}, true)
	if err != nil {
		return nil, err
	}
	h = &store.Host{Meta: meta, Registration: reg}
	return h, s.st.SaveHost(ctx, meta.Issuer, hostKind, h)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := &pending{}
	if err := s.st.AuthRequest(r.Context(), q.Get("state"), p, true); err != nil || p.Issuer == "" {
		s.page(w, http.StatusBadRequest, "Expired", "This sign-in request has expired. Start again from your assistant.", nil)
		return
	}
	if c, err := r.Cookie(authCookie); err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(p.Cookie)) != 1 {
		s.page(w, http.StatusBadRequest, "Sign-in not started here", "This sign-in did not start in this browser. Start again from your assistant.", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: authCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	if e := q.Get("error"); e != "" {
		s.redirectError(w, r, p, "access_denied", "the mail server refused: "+e)
		return
	}
	h, err := s.st.Host(r.Context(), p.Issuer, hostKind)
	if err != nil {
		s.redirectError(w, r, p, "server_error", "unknown mail server")
		return
	}
	if err := mailauth.CheckIssuer(h.Meta, q.Get("iss")); err != nil {
		s.redirectError(w, r, p, "access_denied", err.Error())
		return
	}
	cfg := mailauth.Config(h.Meta, h.Registration, s.base(r)+"/callback")
	tok, err := cfg.Exchange(s.env.Context(r.Context()), q.Get("code"), oauth2.VerifierOption(p.Verifier))
	var sub string
	if err == nil {
		sub, err = mailauth.IDTokenSubject(h.Meta, tok, cfg, p.Nonce)
	}
	if err != nil {
		s.log.Warn("mail token exchange failed", "issuer", p.Issuer, "err", err)
		s.redirectError(w, r, p, "access_denied", "the mail server did not issue a token")
		return
	}
	mc := s.env.Client(cfg, tok, p.SessionURL, nil)
	sess, err := mc.Session(r.Context())
	if err == nil {
		_, err = mc.MailAccount(r.Context())
	}
	if err != nil {
		s.log.Warn("mail session check failed", "issuer", p.Issuer, "err", err)
		s.redirectError(w, r, p, "access_denied", "the mail account cannot be used")
		return
	}
	// The user is the subject of the verified ID token; without OpenID, the session (same domain as the issuer) names it.
	subject, email := sub, p.Email
	if subject == "" {
		subject = sess.Username
	}
	if subject == "" {
		subject = p.Email
	}
	if strings.Contains(sess.Username, "@") {
		email = strings.ToLower(sess.Username)
	}
	userID, err := s.st.UpsertUser(r.Context(), p.Issuer, subject)
	if err == nil {
		var accountID string
		accountID, err = s.st.SaveAccount(r.Context(), &store.Account{UserID: userID, Email: email, Issuer: p.Issuer, SessionURL: p.SessionURL, Token: tok})
		s.forget(userID, accountID)
	}
	code := store.RandomToken("jmcp_c_")
	if err == nil {
		err = s.st.SaveCode(r.Context(), code, &store.Grant{UserID: userID, ClientID: p.ClientID, RedirectURI: p.RedirectURI,
			CodeChallenge: p.CodeChallenge, Resource: p.Resource, Scope: p.Scope}, codeTTL)
	}
	if err != nil {
		s.log.Error("completing authorization", "err", err)
		s.redirectError(w, r, p, "server_error", "")
		return
	}
	s.log.Info("user authorized a client", "issuer", p.Issuer, "client", p.ClientName)
	u, _ := url.Parse(p.RedirectURI)
	rq := u.Query()
	rq.Set("code", code)
	if p.State != "" {
		rq.Set("state", p.State)
	}
	rq.Set("iss", s.base(r))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// authenticateClient checks the client credentials of a token request.
func (s *Server) authenticateClient(r *http.Request) (*store.Client, error) {
	id, secret, basic := r.BasicAuth()
	if basic {
		var err error
		if id, err = url.QueryUnescape(id); err != nil {
			return nil, err
		}
		if secret, err = url.QueryUnescape(secret); err != nil {
			return nil, err
		}
	} else {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	c, err := s.lookupClient(r.Context(), id)
	if err != nil {
		return nil, errors.New("unknown client")
	}
	if c.SecretHash != "" && subtle.ConstantTimeCompare([]byte(s.st.Hash(secret)), []byte(c.SecretHash)) != 1 {
		return nil, errors.New("invalid client credentials")
	}
	return c, nil
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	client, err := s.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	var g *store.Grant
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		if v := r.PostFormValue("code_verifier"); len(v) < 43 || len(v) > 128 {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid code_verifier")
			return
		}
		g, err = s.st.ConsumeCode(r.Context(), r.PostFormValue("code"))
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
			return
		}
		switch {
		case g.ClientID != client.ClientID:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "code issued to another client")
			return
		case g.RedirectURI != r.PostFormValue("redirect_uri"):
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		case subtle.ConstantTimeCompare([]byte(s256(r.PostFormValue("code_verifier"))), []byte(g.CodeChallenge)) != 1:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	case "refresh_token":
		g, err = s.st.RotateRefresh(r.Context(), r.PostFormValue("refresh_token"), client.ClientID)
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
			return
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	if res := r.PostFormValue("resource"); res != "" && !oauthex.MatchesResource([]string{res}, g.Resource) {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource mismatch")
		return
	}
	if !s.st.UserExists(r.Context(), g.UserID) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown user")
		return
	}
	access, refresh := store.RandomToken("jmcp_at_"), store.RandomToken("jmcp_rt_")
	err = s.st.SaveToken(r.Context(), access, store.AccessToken, g, accessTTL)
	if err == nil {
		err = s.st.SaveToken(r.Context(), refresh, store.RefreshToken, g, refreshTTL)
	}
	if err != nil {
		s.log.Error("saving tokens", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds()), "refresh_token": refresh, "scope": g.Scope,
	})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	client, err := s.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	if err := s.st.RevokeToken(r.Context(), r.PostFormValue("token"), client.ClientID); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	w.WriteHeader(http.StatusOK)
}
