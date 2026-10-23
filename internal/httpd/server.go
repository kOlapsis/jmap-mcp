// Package httpd serves MCP over HTTP: OAuth resource server, minimal authorization server and mail-server OAuth client.
package httpd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
	"github.com/kOlapsis/jmap-mcp/internal/store"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

const (
	hostKind      = "web"
	accessTTL     = time.Hour
	refreshTTL    = 30 * 24 * time.Hour
	codeTTL       = 5 * time.Minute
	requestTTL    = 15 * time.Minute
	attachmentTTL = 15 * time.Minute
	mcpScope      = "mail"
)

// Server is the HTTP mode of the bridge.
type Server struct {
	cfg     *config.Config
	st      *store.Store
	env     *mailauth.Env
	log     *slog.Logger
	version string

	mu      sync.Mutex
	servers map[string]*tools.Server
	clients map[string]*jmapc.Client
	cimd    map[string]cachedClient
}

// New opens the store in the data directory, generating the secrets on first start.
func New(cfg *config.Config, version string, log *slog.Logger) (*Server, error) {
	key, source, err := store.MasterKey(cfg.DataDir, false)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DataDir, key)
	if err != nil {
		return nil, err
	}
	log.Info("store opened", "dir", cfg.DataDir, "key", source)
	return &Server{cfg: cfg, st: st, env: mailauth.NewEnv(cfg.Net), log: log, version: version,
		servers: map[string]*tools.Server{}, clients: map[string]*jmapc.Client{}, cimd: map[string]cachedClient{}}, nil
}

// Close releases the store.
func (s *Server) Close() error { return s.st.Close() }

// AdminToken returns the secret protecting the /admin page.
func (s *Server) AdminToken() string { return adminToken(s.st) }

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.logRequests)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	r.Get("/", s.home)
	r.Get("/.well-known/oauth-protected-resource", s.resourceMetadata)
	r.Get("/.well-known/oauth-protected-resource/mcp", s.resourceMetadata)
	r.Get("/.well-known/oauth-authorization-server", s.authServerMetadata)
	r.Get("/.well-known/oauth-authorization-server/mcp", s.authServerMetadata)
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitBy(60, time.Minute, clientIP))
		r.Post("/register", s.register)
		r.Post("/token", s.token)
		r.Post("/revoke", s.revoke)
		r.Group(func(r chi.Router) {
			r.Use(securityHeaders, http.NewCrossOriginProtection().Handler)
			r.Get("/authorize", s.authorize)
			r.Post("/authorize", s.authorizeSubmit)
			r.Get("/callback", s.callback)
			r.Get("/admin", s.admin)
			r.Post("/admin", s.admin)
		})
	})
	r.Get("/attachments/{token}", s.attachment)
	r.Handle("/mcp", s.mcpHandler())
	return r
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	hs := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.st.Purge(ctx); err != nil {
					s.log.Warn("purging expired records", "err", err)
				}
			}
		}
	}()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	s.log.Info("listening", "addr", s.cfg.Listen, "public_url", s.cfg.PublicURL, "send_enabled", s.cfg.EnableSend)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := hs.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// base returns the public base URL: --public-url, or the X-Forwarded-* headers set by the reverse proxy.
func (s *Server) base(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return strings.TrimSuffix(s.cfg.PublicURL, "/")
	}
	return baseFromHeaders(r.Header, r.Host, r.TLS != nil)
}

func baseFromHeaders(h http.Header, host string, tls bool) string {
	proto := "http"
	if tls {
		proto = "https"
	}
	if p := firstValue(h.Get("X-Forwarded-Proto")); p == "https" || p == "http" {
		proto = p
	}
	if fh := firstValue(h.Get("X-Forwarded-Host")); validHost(fh) {
		host = fh
	}
	if !validHost(host) {
		host = "localhost"
	}
	prefix := firstValue(h.Get("X-Forwarded-Prefix"))
	if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "\"'<> ?#\\") {
		prefix = ""
	}
	return proto + "://" + host + strings.TrimSuffix(prefix, "/")
}

func firstValue(v string) string {
	v, _, _ = strings.Cut(v, ",")
	return strings.TrimSpace(v)
}

func validHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	for _, r := range h {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune(".-:[]", r) {
			return false
		}
	}
	return true
}

// clientIP keys rate limits on the address the reverse proxy saw, else the peer address.
func clientIP(r *http.Request) (string, error) {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String(), nil
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, nil
	}
	return host, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests logs method, path and status only: query strings carry codes and are never logged.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		path := r.URL.Path
		if strings.HasPrefix(path, "/attachments/") {
			path = "/attachments/…"
		}
		s.log.Debug("http", "method", r.Method, "path", path, "status", sw.status, "duration", time.Since(start).Round(time.Millisecond))
	})
}
