package httpd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mikluko/jmap"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
	"github.com/kOlapsis/jmap-mcp/internal/mailview"
	"github.com/kOlapsis/jmap-mcp/internal/store"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

// baseHeader carries the public base URL to the tool handlers; it overwrites any client-sent value.
const baseHeader = "X-Jmap-Mcp-Base"

func (s *Server) mcpHandler() http.Handler {
	h := mcp.NewStreamableHTTPHandler(s.serverFor, &mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute, Logger: s.log})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := s.base(r)
		r.Header.Set(baseHeader, base)
		auth.RequireBearerToken(s.verify, &auth.RequireBearerTokenOptions{
			ResourceMetadataURL: base + "/.well-known/oauth-protected-resource/mcp",
			Scopes:              []string{mcpScope},
		})(h).ServeHTTP(w, r)
	})
}

// verify accepts only access tokens issued by this bridge for this resource.
func (s *Server) verify(ctx context.Context, token string, r *http.Request) (*auth.TokenInfo, error) {
	g, err := s.st.Token(ctx, token, store.AccessToken)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: unknown or expired token", auth.ErrInvalidToken)
	}
	if err != nil {
		return nil, err
	}
	if !oauthex.MatchesResource([]string{g.Resource}, s.resource(r)) {
		return nil, fmt.Errorf("%w: token issued for another resource", auth.ErrInvalidToken)
	}
	return &auth.TokenInfo{Scopes: strings.Fields(g.Scope), Expiration: time.Unix(g.ExpiresAt, 0), UserID: g.UserID}, nil
}

// serverFor returns the MCP server of the authenticated user; each user gets its own.
func (s *Server) serverFor(r *http.Request) *mcp.Server {
	ti := auth.TokenInfoFromContext(r.Context())
	if ti == nil || ti.UserID == "" {
		return nil
	}
	s.mu.Lock()
	srv, ok := s.servers[ti.UserID]
	if !ok {
		srv = tools.New(tools.Options{Backend: &userBackend{s: s, user: ti.UserID}, SendEnabled: s.cfg.EnableSend, Mode: "http", Version: s.version, Logger: s.log})
		s.servers[ti.UserID] = srv
	}
	s.mu.Unlock()
	if !ok {
		srv.Sync(r.Context())
	}
	return srv.Server
}

// forget drops cached state after a user re-authorized.
func (s *Server) forget(userID, accountID string) {
	s.mu.Lock()
	delete(s.servers, userID)
	delete(s.clients, accountID)
	s.mu.Unlock()
}

func (s *Server) client(ctx context.Context, a *store.Account) (*jmapc.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[a.ID]; ok {
		return c, nil
	}
	h, err := s.st.Host(ctx, a.Issuer, hostKind)
	if err != nil {
		return nil, err
	}
	id := a.ID
	c := s.env.Client(mailauth.Config(h.Meta, h.Registration, ""), a.Token, a.SessionURL, func(t *oauth2.Token) {
		if err := s.st.UpdateToken(context.Background(), id, t); err != nil {
			s.log.Error("saving refreshed mail token", "err", err)
		}
	})
	s.clients[a.ID] = c
	return c, nil
}

type userBackend struct {
	s    *Server
	user string
}

func (b *userBackend) Accounts(ctx context.Context) ([]*tools.Account, error) {
	rows, err := b.s.st.Accounts(ctx, b.user)
	if err != nil {
		return nil, err
	}
	out := make([]*tools.Account, 0, len(rows))
	for _, r := range rows {
		c, err := b.s.client(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, &tools.Account{Email: r.Email, Client: c, Default: r.Default})
	}
	return out, nil
}

func (b *userBackend) SetDefault(ctx context.Context, email string) error {
	if err := b.s.st.SetDefault(ctx, b.user, email); err != nil {
		return fmt.Errorf("unknown account %q", email)
	}
	return nil
}

type attachmentClaims struct {
	User    string `json:"u"`
	Email   string `json:"m"`
	Account string `json:"a"`
	Blob    string `json:"b"`
	Name    string `json:"n,omitempty"`
	Type    string `json:"t,omitempty"`
	Expires int64  `json:"e"`
}

// AttachmentLink returns a short-lived signed URL served by the bridge.
func (b *userBackend) AttachmentLink(_ context.Context, req *mcp.CallToolRequest, acct *tools.Account, accountID jmap.ID, att mailview.Attachment) (string, error) {
	base := b.s.cfg.PublicURL
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		base = req.Extra.Header.Get(baseHeader)
	}
	if base == "" {
		return "", errors.New("the public URL of the bridge is unknown")
	}
	payload, err := json.Marshal(attachmentClaims{User: b.user, Email: acct.Email, Account: string(accountID), Blob: att.ID,
		Name: att.Name, Type: att.Type, Expires: time.Now().Add(attachmentTTL).Unix()})
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return strings.TrimSuffix(base, "/") + "/attachments/" + p + "." + b.s.sign(p), nil
}

func (s *Server) sign(payload string) string {
	m := hmac.New(sha256.New, s.st.Key("attachment-url"))
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) attachment(w http.ResponseWriter, r *http.Request) {
	p, sig, _ := strings.Cut(chi.URLParam(r, "token"), ".")
	var c attachmentClaims
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || !hmac.Equal([]byte(sig), []byte(s.sign(p))) || json.Unmarshal(b, &c) != nil || time.Now().Unix() > c.Expires {
		http.Error(w, "invalid or expired link", http.StatusNotFound)
		return
	}
	rows, err := s.st.Accounts(r.Context(), c.User)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	var acct *store.Account
	for _, a := range rows {
		if a.Email == c.Email {
			acct = a
		}
	}
	if acct == nil {
		http.Error(w, "invalid or expired link", http.StatusNotFound)
		return
	}
	mc, err := s.client(r.Context(), acct)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := mc.Download(r.Context(), jmap.ID(c.Account), jmap.ID(c.Blob), c.Name, c.Type)
	if err != nil {
		s.log.Warn("attachment download failed", "err", err)
		http.Error(w, "download failed", http.StatusBadGateway)
		return
	}
	defer body.Close()
	name := c.Name
	if name == "" {
		name = "attachment"
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "private, no-store")
	h.Set("Referrer-Policy", "no-referrer")
	_, _ = io.Copy(w, body)
}
