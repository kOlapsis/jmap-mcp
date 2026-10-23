package stdio

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/config"
	"github.com/kOlapsis/jmap-mcp/internal/jmapc"
	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
	"github.com/kOlapsis/jmap-mcp/internal/store"
	"github.com/kOlapsis/jmap-mcp/internal/tools"
)

const (
	hostKind        = "loopback"
	loopbackURI     = "http://127.0.0.1/callback"
	connectTimeout  = 10 * time.Minute
	interactiveWait = 90 * time.Second
)

// manager owns the local accounts: OAuth flows, encrypted token storage and JMAP clients.
type manager struct {
	env      *mailauth.Env
	st       *store.Store
	log      *slog.Logger
	onChange func()
	browser  func(string) error

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	clients map[string]*jmapc.Client
}

func newManager(cfg *config.Config, log *slog.Logger) (*manager, error) {
	key, source, err := store.MasterKey(cfg.DataDir, true)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DataDir, key)
	if err != nil {
		return nil, err
	}
	log.Debug("local store opened", "dir", cfg.DataDir, "key", source)
	if _, err := st.UpsertUser(context.Background(), "", store.LocalUser); err != nil {
		st.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &manager{env: mailauth.NewEnv(cfg.Net), st: st, log: log, browser: openBrowser, ctx: ctx, cancel: cancel, clients: map[string]*jmapc.Client{}}, nil
}

func (m *manager) Close() {
	m.cancel()
	m.st.Close()
}

func (m *manager) Accounts(ctx context.Context) ([]*tools.Account, error) {
	rows, err := m.st.Accounts(ctx, store.LocalUser)
	if err != nil {
		return nil, err
	}
	out := make([]*tools.Account, 0, len(rows))
	for _, r := range rows {
		c, err := m.client(ctx, r)
		if err != nil {
			m.log.Warn("account unavailable", "email", r.Email, "err", err)
			continue
		}
		out = append(out, &tools.Account{Email: r.Email, Client: c, Default: r.Default})
	}
	return out, nil
}

func (m *manager) client(ctx context.Context, r *store.Account) (*jmapc.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[r.ID]; ok {
		return c, nil
	}
	h, err := m.st.Host(ctx, r.Issuer, hostKind)
	if err != nil {
		return nil, err
	}
	id := r.ID
	c := m.env.Client(mailauth.Config(h.Meta, h.Registration, ""), r.Token, r.SessionURL, func(t *oauth2.Token) {
		if err := m.st.UpdateToken(context.Background(), id, t); err != nil {
			m.log.Error("saving refreshed token", "err", err)
		}
	})
	m.clients[r.ID] = c
	return c, nil
}

func (m *manager) SetDefault(ctx context.Context, email string) error {
	if err := m.st.SetDefault(ctx, store.LocalUser, email); err != nil {
		return fmt.Errorf("unknown account %q", email)
	}
	return nil
}

// Connect discovers the mail server of email and starts its sign-in flow.
func (m *manager) Connect(ctx context.Context, email string, device bool) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	srv, err := m.env.Discover(ctx, email)
	if err != nil {
		return "", err
	}
	h, err := m.host(ctx, srv.Meta)
	if err != nil {
		return "", err
	}
	if device {
		return m.deviceFlow(ctx, email, srv, h)
	}
	return m.browserFlow(ctx, email, srv, h)
}

func (m *manager) host(ctx context.Context, meta *mailauth.Meta) (*store.Host, error) {
	if h, err := m.st.Host(ctx, meta.Issuer, hostKind); err == nil {
		h.Meta = meta
		return h, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	reg, err := m.env.Register(ctx, meta, "jmap-mcp (local)", []string{loopbackURI}, false)
	if err != nil {
		return nil, err
	}
	h := &store.Host{Meta: meta, Registration: reg}
	return h, m.st.SaveHost(ctx, meta.Issuer, hostKind, h)
}

type callback struct {
	code, iss string
	err       error
}

func (m *manager) browserFlow(ctx context.Context, email string, srv *mailauth.Server, h *store.Host) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	cfg := mailauth.Config(h.Meta, h.Registration, redirect)
	state, verifier := store.RandomToken(""), oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("login_hint", email))
	if err := m.browser(authURL); err != nil {
		ln.Close()
		m.log.Info("could not open a browser", "err", err)
		if h.Meta.DeviceAuthorizationEndpoint != "" {
			return m.deviceFlow(ctx, email, srv, h)
		}
		return fmt.Sprintf("Open this address in a browser on this computer to sign in to %s, then call list_accounts: %s", email, authURL), nil
	}

	results := make(chan callback, 1)
	hs := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/callback" || q.Get("state") != state {
			http.NotFound(w, r)
			return
		}
		res := callback{code: q.Get("code"), iss: q.Get("iss")}
		if e := q.Get("error"); e != "" {
			res.err = fmt.Errorf("sign-in refused: %s %s", e, q.Get("error_description"))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		msg := "Signed in. You can close this window and return to your assistant."
		if res.err != nil {
			msg = res.err.Error()
		}
		fmt.Fprintf(w, "<!doctype html><title>jmap-mcp</title><p>%s</p>", html.EscapeString(msg))
		select {
		case results <- res:
		default:
		}
	})}
	go func() { _ = hs.Serve(ln) }()

	done := make(chan error, 1)
	go func() {
		defer hs.Close()
		wait, cancel := context.WithTimeout(m.ctx, connectTimeout)
		defer cancel()
		select {
		case <-wait.Done():
			done <- errors.New("sign-in timed out")
		case res := <-results:
			if res.err == nil {
				res.err = mailauth.CheckIssuer(h.Meta, res.iss)
			}
			if res.err == nil {
				var tok *oauth2.Token
				tok, res.err = cfg.Exchange(m.env.Context(wait), res.code, oauth2.VerifierOption(verifier))
				if res.err == nil {
					res.err = m.finish(wait, email, srv, h, tok)
				}
			}
			done <- res.err
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Account %s connected.", email), nil
	case <-time.After(interactiveWait):
		return fmt.Sprintf("A browser window was opened to sign in to %s. It is still waiting; once the user has signed in, the account appears in list_accounts. If no window appeared, open: %s", email, authURL), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (m *manager) deviceFlow(ctx context.Context, email string, srv *mailauth.Server, h *store.Host) (string, error) {
	if h.Meta.DeviceAuthorizationEndpoint == "" {
		return "", errors.New("the mail server does not support the device flow; retry without device_flow")
	}
	cfg := mailauth.Config(h.Meta, h.Registration, "")
	da, err := cfg.DeviceAuth(m.env.Context(ctx))
	if err != nil {
		return "", fmt.Errorf("device authorization: %w", err)
	}
	go func() {
		wait, cancel := context.WithTimeout(m.ctx, connectTimeout)
		defer cancel()
		tok, err := cfg.DeviceAccessToken(m.env.Context(wait), da)
		if err == nil {
			err = m.finish(wait, email, srv, h, tok)
		}
		if err != nil {
			m.log.Warn("device sign-in failed", "email", email, "err", err)
		}
	}()
	where := da.VerificationURI
	if da.VerificationURIComplete != "" {
		where = da.VerificationURIComplete
	}
	return fmt.Sprintf("To connect %s, open %s and enter the code %s. Once done, the account appears in list_accounts.", email, where, da.UserCode), nil
}

// finish checks the new token against the JMAP session and stores the account.
func (m *manager) finish(ctx context.Context, email string, srv *mailauth.Server, h *store.Host, tok *oauth2.Token) error {
	c := m.env.Client(mailauth.Config(h.Meta, h.Registration, ""), tok, srv.SessionURL, nil)
	if _, err := c.MailAccount(ctx); err != nil {
		return err
	}
	id, err := m.st.SaveAccount(ctx, &store.Account{UserID: store.LocalUser, Email: email, Issuer: h.Meta.Issuer, SessionURL: srv.SessionURL, Token: tok})
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.clients, id)
	m.mu.Unlock()
	m.log.Info("account connected", "email", email)
	if m.onChange != nil {
		m.onChange()
	}
	return nil
}

func openBrowser(u string) error {
	if runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("no graphical session")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
