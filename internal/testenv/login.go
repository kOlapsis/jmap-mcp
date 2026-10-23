package testenv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
)

// Login runs the real OAuth flow (discovery, public registration, PKCE) for a user and returns a JMAP client.
func (s *Stalwart) Login(t testing.TB, email, password string) *jmapc.Client {
	t.Helper()
	ctx := context.Background()
	env := mailauth.NewEnv(s.Net())
	srv, err := env.Discover(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := env.Register(ctx, srv.Meta, "jmap-mcp test", []string{"http://127.0.0.1/callback"}, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := mailauth.Config(srv.Meta, reg, "http://127.0.0.1:9/callback")
	verifier := oauth2.GenerateVerifier()
	redirect, err := s.Authorize(cfg.AuthCodeURL("st", oauth2.S256ChallengeOption(verifier)), email, password)
	if err != nil {
		t.Fatal(err)
	}
	ru, _ := url.Parse(redirect)
	tok, err := cfg.Exchange(env.Context(ctx), ru.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}
	c := env.Client(cfg, tok, srv.SessionURL, nil)
	if dir := os.Getenv("JMAP_MCP_RECORD"); dir != "" {
		c.HTTP.Transport = &recorder{base: c.HTTP.Transport, dir: dir}
	}
	return c
}

// recorder dumps JMAP exchanges to numbered files, to refresh the unit test fixtures.
type recorder struct {
	base http.RoundTripper
	dir  string
	mu   sync.Mutex
	n    int
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	r.mu.Lock()
	r.n++
	n := r.n
	r.mu.Unlock()
	ex := Exchange{Method: req.Method, Path: req.URL.Path, Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type")}
	if json.Valid(reqBody) {
		ex.Request = reqBody
	} else if len(reqBody) > 0 {
		ex.RequestBody = reqBody
	}
	if strings.Contains(ex.ContentType, "json") && json.Valid(respBody) {
		ex.Response = respBody
	} else {
		ex.Body = respBody
	}
	out, _ := json.MarshalIndent(ex, "", "  ")
	_ = os.WriteFile(filepath.Join(r.dir, fmt.Sprintf("%03d.json", n)), out, 0o644)
	return resp, nil
}
