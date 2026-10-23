package httpd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeMail is a JMAP server with its own OAuth authorization server that approves every sign-in as alice.
type fakeMail struct {
	*httptest.Server
	mu         sync.Mutex
	challenges map[string]string
	refreshes  int
	closedReg  bool
}

const mailIssuer = "https://example.com"

func newFakeMail(t *testing.T) *fakeMail {
	f := &fakeMail{challenges: map[string]string{}}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/jmap", http.RedirectHandler("/jmap/session", http.StatusTemporaryRedirect))
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": mailIssuer, "authorization_endpoint": mailIssuer + "/authorize", "token_endpoint": mailIssuer + "/token",
			"registration_endpoint": mailIssuer + "/register", "response_types_supported": []string{"code"},
			"code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"urn:ietf:params:oauth:scope:mail", "offline_access"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "authorization_response_iss_parameter_supported": true,
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["token_endpoint_auth_method"] != "none" || f.closedReg {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "bridge-public", "redirect_uris": req["redirect_uris"], "token_endpoint_auth_method": "none"})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if (q.Get("client_id") != "bridge-public" && q.Get("client_id") != "static-client") || q.Get("code_challenge_method") != "S256" || q.Get("login_hint") != "alice@example.com" {
			http.Error(w, "bad authorization request", http.StatusBadRequest)
			return
		}
		code := "mailcode-" + q.Get("state")[:8]
		f.mu.Lock()
		f.challenges[code] = q.Get("code_challenge")
		f.mu.Unlock()
		u, _ := url.Parse(q.Get("redirect_uri"))
		u.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {mailIssuer}}.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		if id, secret, _ := r.BasicAuth(); id == "static-client" && secret != "static-secret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		switch r.PostFormValue("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
			if f.challenges[r.PostFormValue("code")] != base64.RawURLEncoding.EncodeToString(sum[:]) {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
		case "refresh_token":
			f.refreshes++
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "mail-access", "token_type": "bearer", "expires_in": 3600, "refresh_token": "mail-refresh"})
	})
	mux.HandleFunc("/jmap/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mail-access" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"capabilities":{"urn:ietf:params:jmap:core":{},"urn:ietf:params:jmap:mail":{}},
			"accounts":{"A":{"name":"alice@example.com","isPersonal":true,"accountCapabilities":{"urn:ietf:params:jmap:mail":{}}}},
			"primaryAccounts":{"urn:ietf:params:jmap:mail":"A"},"username":"alice@example.com","state":"s",
			"apiUrl":"https://example.com/jmap/","downloadUrl":"https://example.com/jmap/download/{accountId}/{blobId}/{name}?accept={type}","uploadUrl":"https://example.com/jmap/upload/{accountId}/"}`)
	})
	mux.HandleFunc("/jmap/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mail-access" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"methodResponses":[["Mailbox/get",{"accountId":"A","state":"1","list":[{"id":"inbox","name":"Inbox","role":"inbox","totalEmails":3,"unreadEmails":1}]},"0"]],"sessionState":"s"}`)
	})
	mux.HandleFunc("/jmap/download/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mail-access" || !strings.HasPrefix(r.URL.Path, "/jmap/download/A/blob1/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("%PDF-1.7 fake"))
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}
