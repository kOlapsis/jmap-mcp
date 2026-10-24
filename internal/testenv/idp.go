package testenv

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// AuthHost is the name of the test OpenID provider.
const AuthHost = "auth." + Domain

// IdP is a minimal OpenID provider modelled on Authentik (one public client, no dynamic registration, JWT access tokens, rotating refresh tokens) that signs in every user as Email.
type IdP struct {
	Issuer   string
	ClientID string
	Email    string
	Redirect *regexp.Regexp

	hostPort, addr, authURL string
	key                     *rsa.PrivateKey

	mu        sync.Mutex
	codes     map[string]url.Values
	refresh   map[string]string
	scopes    []string
	refreshes int
}

// StartIdP serves an OpenID provider for clientID, reachable from the Stalwart container.
func StartIdP(t testing.TB, clientID, email string) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":0") //nolint:gosec // the container connects through the Docker host gateway
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	p := &IdP{ClientID: clientID, Email: email, Redirect: regexp.MustCompile(`^$`), key: key,
		hostPort: fmt.Sprintf("%s:%d", AuthHost, port), addr: fmt.Sprintf("127.0.0.1:%d", port),
		codes: map[string]url.Values{}, refresh: map[string]string{}}
	base := "http://" + p.hostPort + "/application/o/"
	p.Issuer, p.authURL = base+clientID+"/", base+"authorize/"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /application/o/"+clientID+"/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer": p.Issuer, "authorization_endpoint": p.authURL, "token_endpoint": base + "token/", "userinfo_endpoint": base + "userinfo/", "jwks_uri": p.Issuer + "jwks/",
			"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
			"scopes_supported": []string{"openid", "email", "profile", "offline_access"}, "subject_types_supported": []string{"public"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
			"code_challenge_methods_supported":      []string{"plain", "S256"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /application/o/"+clientID+"/jwks/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("POST /application/o/token/", p.token)
	mux.HandleFunc("GET /application/o/userinfo/", func(w http.ResponseWriter, r *http.Request) {
		if !p.verify(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		c := p.claims(p.ClientID, "")
		writeJSON(w, http.StatusOK, map[string]any{"sub": c["sub"], "email": c["email"], "email_verified": true, "preferred_username": c["preferred_username"]})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return p
}

// Authorize plays the user's browser on the IdP for an authorization URL and returns the redirect with the code.
func (p *IdP) Authorize(authURL string) (string, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	switch {
	case u.Scheme+"://"+u.Host+u.Path != p.authURL:
		return "", fmt.Errorf("not the authorization endpoint of the IdP: %s", authURL)
	case q.Get("client_id") != p.ClientID || q.Get("response_type") != "code":
		return "", errors.New("unknown client or response type")
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		return "", errors.New("PKCE S256 required")
	case !p.Redirect.MatchString(q.Get("redirect_uri")):
		return "", fmt.Errorf("redirect URI not allowed: %s", q.Get("redirect_uri"))
	case !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		return "", errors.New("scope openid missing")
	}
	code := randomString(32)
	p.mu.Lock()
	p.codes[code] = q
	p.scopes = append(p.scopes, q.Get("scope"))
	p.mu.Unlock()
	ru, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		return "", err
	}
	rq := ru.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	ru.RawQuery = rq.Encode()
	return ru.String(), nil
}

// Scopes returns the scope parameter of every authorization request, in order.
func (p *IdP) Scopes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.scopes)
}

// Refreshes returns the number of refresh token grants served.
func (p *IdP) Refreshes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshes
}

// AccessToken signs an access token for Email with the given audience.
func (p *IdP) AccessToken(audience string) string {
	return p.sign(p.claims(audience, "openid email"))
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("client_id") != p.ClientID {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var scope, nonce string
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		q, ok := p.codes[r.PostFormValue("code")]
		delete(p.codes, r.PostFormValue("code"))
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || q.Get("redirect_uri") != r.PostFormValue("redirect_uri") || b64(sum[:]) != q.Get("code_challenge") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		scope, nonce = q.Get("scope"), q.Get("nonce")
	case "refresh_token":
		var ok bool
		if scope, ok = p.refresh[r.PostFormValue("refresh_token")]; !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		delete(p.refresh, r.PostFormValue("refresh_token"))
		p.refreshes++
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	id := p.claims(p.ClientID, "")
	id["nonce"] = nonce
	resp := map[string]any{"access_token": p.sign(p.claims(p.ClientID, scope)), "token_type": "Bearer", "expires_in": 300, "scope": scope, "id_token": p.sign(id)}
	if slices.Contains(strings.Fields(scope), "offline_access") {
		rt := randomString(32)
		p.refresh[rt] = scope
		resp["refresh_token"] = rt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (p *IdP) claims(audience, scope string) map[string]any {
	now := time.Now()
	c := map[string]any{"iss": p.Issuer, "sub": "user-1", "aud": audience, "azp": audience, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"email": p.Email, "email_verified": true, "preferred_username": strings.Split(p.Email, "@")[0]}
	if scope != "" {
		c["scope"] = scope
	}
	return c
}

func (p *IdP) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(nil, p.key, crypto.SHA256, sum[:])
	return in + "." + b64(sig)
}

func (p *IdP) verify(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return err == nil && rsa.VerifyPKCS1v15(&p.key.PublicKey, crypto.SHA256, sum[:], sig) == nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
