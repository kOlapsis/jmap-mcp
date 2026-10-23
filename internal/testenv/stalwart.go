// Package testenv starts a disposable Stalwart server in Docker for integration tests.
package testenv

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kOlapsis/jmap-mcp/internal/netguard"
)

// Image is the Stalwart image used by the integration tests.
const Image = "stalwartlabs/stalwart:v0.16.27"

// Host and Domain are the names Stalwart is configured with; the tests map them to the container.
const (
	Host   = "mail.example.test"
	Domain = "example.test"
)

// Stalwart is a running container.
type Stalwart struct {
	Addr      string
	AdminUser string
	AdminPass string
	name      string
	hc        *http.Client
}

// Start runs Stalwart, completes its bootstrap through the API and waits until it serves HTTPS.
func Start(t testing.TB) *Stalwart {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	s := &Stalwart{name: fmt.Sprintf("jmap-mcp-test-%d", time.Now().UnixNano())}
	bootPass := randomString(16)
	run(t, "docker", "run", "-d", "--rm", "--name", s.name, "-e", "STALWART_RECOVERY_ADMIN=admin:"+bootPass,
		"-p", "127.0.0.1::443", "-p", "127.0.0.1::8080", Image)
	t.Cleanup(func() {
		if os.Getenv("JMAP_MCP_KEEP_CONTAINER") == "" {
			_ = exec.Command("docker", "rm", "-f", s.name).Run()
		}
	})
	bootAddr := s.port(t, "8080")
	s.hc = (netguard.Options{AllowPrivate: true, AllowHTTP: true, InsecureTLS: true}).Client(30 * time.Second)

	var setup struct {
		MethodResponses [][]json.RawMessage `json:"methodResponses"`
	}
	waitFor(t, func() error {
		return s.call("http://"+bootAddr+"/jmap", "admin", bootPass, []any{
			[]any{"x:Bootstrap/set", map[string]any{"update": map[string]any{"singleton": map[string]any{
				"serverHostname": Host, "defaultDomain": Domain, "requestTlsCertificate": false, "generateDkimKeys": false,
			}}}, "0"},
		}, &setup)
	})
	var created struct {
		Updated map[string]struct {
			Username string `json:"username"`
			Secret   string `json:"secret"`
		} `json:"updated"`
	}
	if len(setup.MethodResponses) == 0 || json.Unmarshal(setup.MethodResponses[0][1], &created) != nil || created.Updated["singleton"].Secret == "" {
		t.Fatalf("stalwart bootstrap failed: %+v", setup)
	}
	s.AdminUser, s.AdminPass = created.Updated["singleton"].Username, created.Updated["singleton"].Secret
	run(t, "docker", "restart", s.name)
	s.Addr = s.port(t, "443")
	waitFor(t, func() error {
		resp, err := s.hc.Get("https://" + s.Addr + "/.well-known/oauth-authorization-server")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	})
	return s
}

// Net returns guard options mapping the Stalwart names to the container.
func (s *Stalwart) Net() netguard.Options {
	return netguard.Options{AllowPrivate: true, InsecureTLS: true, Resolve: map[string]string{
		Host + ":443": s.Addr, Domain + ":443": s.Addr,
	}}
}

// CreateUser creates a mailbox user and returns its address.
func (s *Stalwart) CreateUser(t testing.TB, name, password string) string {
	t.Helper()
	res := s.JMAP(t, s.AdminUser, s.AdminPass, []any{[]any{"x:Domain/query", map[string]any{}, "d"}})
	var domains struct{ IDs []string }
	if json.Unmarshal(res[0][1], &domains) != nil || len(domains.IDs) == 0 {
		t.Fatalf("no domain: %s", res[0][1])
	}
	res = s.JMAP(t, s.AdminUser, s.AdminPass, []any{
		[]any{"x:Account/set", map[string]any{"create": map[string]any{"u": map[string]any{
			"@type": "User", "name": name, "domainId": domains.IDs[0],
			"credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": password}},
			"roles":       map[string]any{"@type": "User"},
		}}}, "a"},
	})
	if !bytes.Contains(res[0][1], []byte(`"created"`)) {
		t.Fatalf("create user %s: %s", name, res[0][1])
	}
	return name + "@" + Domain
}

// JMAP sends a raw JMAP request as user with basic authentication.
func (s *Stalwart) JMAP(t testing.TB, user, password string, calls []any) [][]json.RawMessage {
	t.Helper()
	var out struct {
		MethodResponses [][]json.RawMessage `json:"methodResponses"`
	}
	if err := s.call("https://"+s.Addr+"/jmap", user, password, calls, &out); err != nil {
		t.Fatal(err)
	}
	return out.MethodResponses
}

// Seed imports RFC 5322 messages into the inbox of user and returns their ids in order.
func (s *Stalwart) Seed(t testing.TB, user, password string, messages ...string) []string {
	t.Helper()
	accountID := s.AccountID(t, user, password)
	res := s.JMAP(t, user, password, []any{[]any{"Mailbox/get", map[string]any{"accountId": accountID}, "m"}})
	var mbs struct {
		List []struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"list"`
	}
	_ = json.Unmarshal(res[0][1], &mbs)
	inbox := ""
	for _, m := range mbs.List {
		if m.Role == "inbox" {
			inbox = m.ID
		}
	}
	if inbox == "" {
		t.Fatalf("no inbox for %s: %s", user, res[0][1])
	}
	imports := map[string]any{}
	for i, msg := range messages {
		req, _ := http.NewRequest(http.MethodPost, "https://"+s.Addr+"/jmap/upload/"+accountID+"/", strings.NewReader(strings.ReplaceAll(msg, "\n", "\r\n")))
		req.SetBasicAuth(user, password)
		req.Header.Set("Content-Type", "message/rfc822")
		resp, err := s.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var up struct {
			BlobID string `json:"blobId"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&up)
		resp.Body.Close()
		entry := map[string]any{"blobId": up.BlobID, "mailboxIds": map[string]bool{inbox: true}, "keywords": map[string]bool{}}
		if m, err := mail.ReadMessage(strings.NewReader(msg)); err == nil {
			if d, err := m.Header.Date(); err == nil {
				entry["receivedAt"] = d.UTC().Format(time.RFC3339)
			}
		}
		imports[fmt.Sprint(i)] = entry
	}
	res = s.JMAP(t, user, password, []any{[]any{"Email/import", map[string]any{"accountId": accountID, "emails": imports}, "i"}})
	var imp struct {
		Created    map[string]struct{ ID string } `json:"created"`
		NotCreated map[string]any                 `json:"notCreated"`
	}
	_ = json.Unmarshal(res[0][1], &imp)
	if len(imp.NotCreated) > 0 || len(imp.Created) != len(messages) {
		t.Fatalf("import failed: %s", res[0][1])
	}
	ids := make([]string, len(messages))
	for i := range messages {
		ids[i] = imp.Created[fmt.Sprint(i)].ID
	}
	return ids
}

// AccountID returns the primary mail account id of user.
func (s *Stalwart) AccountID(t testing.TB, user, password string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://"+s.Addr+"/jmap/session", nil)
	req.SetBasicAuth(user, password)
	resp, err := s.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sess struct {
		PrimaryAccounts map[string]string `json:"primaryAccounts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil || sess.PrimaryAccounts["urn:ietf:params:jmap:mail"] == "" {
		t.Fatalf("session of %s: %v", user, err)
	}
	return sess.PrimaryAccounts["urn:ietf:params:jmap:mail"]
}

// Authorize plays the user's browser on Stalwart's login page for an authorization URL.
// It returns the redirect URI with the code, state and iss parameters appended.
func (s *Stalwart) Authorize(authURL, user, password string) (string, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	body := map[string]any{
		"type": "authCode", "accountName": user, "accountSecret": password,
		"clientId": q.Get("client_id"), "redirectUri": q.Get("redirect_uri"), "scope": q.Get("scope"),
		"codeChallenge": q.Get("code_challenge"), "codeChallengeMethod": q.Get("code_challenge_method"),
		"state": q.Get("state"), "nonce": q.Get("nonce"),
	}
	var out struct {
		Type       string `json:"type"`
		ClientCode string `json:"client_code"`
		Iss        string `json:"iss"`
	}
	if err := s.post("/api/auth", body, &out); err != nil {
		return "", err
	}
	if out.ClientCode == "" {
		return "", fmt.Errorf("stalwart login: %s", out.Type)
	}
	ru, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		return "", err
	}
	rq := ru.Query()
	rq.Set("code", out.ClientCode)
	rq.Set("state", q.Get("state"))
	rq.Set("iss", out.Iss)
	ru.RawQuery = rq.Encode()
	return ru.String(), nil
}

// ApproveDevice enters a device-flow user code as user.
func (s *Stalwart) ApproveDevice(userCode, user, password string) error {
	var out struct {
		Type string `json:"type"`
	}
	if err := s.post("/api/auth", map[string]any{"type": "authDevice", "accountName": user, "accountSecret": password, "code": userCode}, &out); err != nil {
		return err
	}
	if out.Type != "verified" && out.Type != "authenticated" {
		return fmt.Errorf("device approval: %s", out.Type)
	}
	return nil
}

func (s *Stalwart) post(path string, body, out any) error {
	b, _ := json.Marshal(body)
	resp, err := s.hc.Post("https://"+s.Addr+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d %s", path, resp.StatusCode, data)
	}
	return json.Unmarshal(data, out)
}

func (s *Stalwart) call(endpoint, user, pass string, calls []any, out any) error {
	b, _ := json.Marshal(map[string]any{"using": []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:stalwart:jmap"}, "methodCalls": calls})
	req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, data)
	}
	return json.Unmarshal(data, out)
}

func (s *Stalwart) port(t testing.TB, p string) string {
	t.Helper()
	out, err := exec.Command("docker", "port", s.name, p).Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	return strings.TrimSpace(strings.Split(string(out), "\n")[0])
}

// PKCE returns a verifier and its S256 challenge.
func PKCE() (verifier, challenge string) {
	verifier = randomString(43)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func run(t testing.TB, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func waitFor(t testing.TB, f func() error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var err error
	for ctx.Err() == nil {
		if err = f(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for stalwart: %v", err)
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}
