// Package jmapc is a thin JMAP (RFC 8620/8621) client over github.com/mikluko/jmap types.
package jmapc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/mikluko/jmap"

	// Register the method responses decoded by Do.
	_ "github.com/mikluko/jmap/mail/email"
	_ "github.com/mikluko/jmap/mail/emailsubmission"
	_ "github.com/mikluko/jmap/mail/identity"
	_ "github.com/mikluko/jmap/mail/mailbox"
	_ "github.com/mikluko/jmap/mail/thread"
	_ "github.com/mikluko/jmap/mail/vacationresponse"
	_ "github.com/mikluko/jmap/sieve/sievescript"
)

// Capability URIs used by this project.
const (
	CapCore       jmap.URI = "urn:ietf:params:jmap:core"
	CapMail       jmap.URI = "urn:ietf:params:jmap:mail"
	CapSubmission jmap.URI = "urn:ietf:params:jmap:submission"
	CapVacation   jmap.URI = "urn:ietf:params:jmap:vacationresponse"
	CapSieve      jmap.URI = "urn:ietf:params:jmap:sieve"
)

const maxResponseBytes = 32 << 20

// Client talks to one JMAP server with an already authenticated HTTP client.
type Client struct {
	HTTP       *http.Client
	SessionURL string

	mu      sync.Mutex
	session *Session
}

// Session is the subset of the JMAP session resource this project reads.
// Capabilities stay raw so that unknown server extensions never break decoding.
type Session struct {
	Capabilities    map[jmap.URI]json.RawMessage `json:"capabilities"`
	Accounts        map[jmap.ID]Account          `json:"accounts"`
	PrimaryAccounts map[jmap.URI]jmap.ID         `json:"primaryAccounts"`
	Username        string                       `json:"username"`
	APIURL          string                       `json:"apiUrl"`
	DownloadURL     string                       `json:"downloadUrl"`
	UploadURL       string                       `json:"uploadUrl"`
	State           string                       `json:"state"`
}

// Account is a JMAP account entry of the session.
type Account struct {
	Name         string                       `json:"name"`
	IsPersonal   bool                         `json:"isPersonal"`
	IsReadOnly   bool                         `json:"isReadOnly"`
	Capabilities map[jmap.URI]json.RawMessage `json:"accountCapabilities"`
}

// Session returns the cached JMAP session, fetching it on first use.
func (c *Client) Session(ctx context.Context) (*Session, error) {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s != nil {
		return s, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.SessionURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jmap session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, httpError(resp)
	}
	s = &Session{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(s); err != nil {
		return nil, fmt.Errorf("jmap session: %w", err)
	}
	if s.APIURL == "" {
		return nil, fmt.Errorf("jmap session: missing apiUrl")
	}
	for _, u := range []*string{&s.APIURL, &s.DownloadURL, &s.UploadURL} {
		*u = resolveRef(c.SessionURL, *u)
	}
	c.mu.Lock()
	c.session = s
	c.mu.Unlock()
	return s, nil
}

// Invalidate drops the cached session so the next call refetches it.
func (c *Client) Invalidate() {
	c.mu.Lock()
	c.session = nil
	c.mu.Unlock()
}

// HasCapability reports whether the session advertises the capability.
func (c *Client) HasCapability(ctx context.Context, uri jmap.URI) bool {
	s, err := c.Session(ctx)
	if err != nil {
		return false
	}
	_, ok := s.Capabilities[uri]
	return ok
}

// MailAccount returns the primary mail account id.
func (c *Client) MailAccount(ctx context.Context) (jmap.ID, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return "", err
	}
	if id, ok := s.PrimaryAccounts[CapMail]; ok {
		return id, nil
	}
	return "", fmt.Errorf("jmap: the server has no primary mail account")
}

// Do sends a request and returns the decoded response.
func (c *Client) Do(ctx context.Context, req *jmap.Request) (*jmap.Response, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	using := []jmap.URI{CapCore}
	for _, u := range req.Using {
		if u == CapCore {
			continue
		}
		if _, ok := s.Capabilities[u]; !ok {
			return nil, fmt.Errorf("jmap: the server does not support %s", u)
		}
		using = append(using, u)
	}
	req.Using = using
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.APIURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("jmap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, httpError(resp)
	}
	out := &jmap.Response{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return nil, fmt.Errorf("jmap: decoding response: %w", err)
	}
	if out.SessionState != "" && out.SessionState != s.State {
		c.Invalidate()
	}
	return out, nil
}

// Result extracts the response of callID from resp.
func Result[T any](resp *jmap.Response, callID string) (T, error) {
	var zero T
	for _, inv := range resp.Responses {
		if inv.CallID != callID {
			continue
		}
		if merr, ok := inv.Args.(*jmap.MethodError); ok {
			return zero, &MethodError{Type: merr.Type, Description: deref(merr.Description)}
		}
		if v, ok := inv.Args.(T); ok {
			return v, nil
		}
	}
	return zero, fmt.Errorf("jmap: no %T response for call %s", zero, callID)
}

// Upload stores a blob and returns its id.
func (c *Client) Upload(ctx context.Context, accountID jmap.ID, contentType string, data io.Reader) (*jmap.UploadResponse, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	u := strings.ReplaceAll(s.UploadURL, "{accountId}", url.PathEscape(string(accountID)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, data)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jmap upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, httpError(resp)
	}
	out := &jmap.UploadResponse{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return nil, fmt.Errorf("jmap upload: %w", err)
	}
	return out, nil
}

// Download opens a blob. The caller must close the returned body.
func (c *Client) Download(ctx context.Context, accountID, blobID jmap.ID, name, contentType string) (io.ReadCloser, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "attachment"
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	// The template mixes path and query variables (RFC 8620 §2), so escape for both.
	u := strings.NewReplacer(
		"{accountId}", url.PathEscape(string(accountID)),
		"{blobId}", url.PathEscape(string(blobID)),
		"{name}", url.PathEscape(name),
		"{type}", url.QueryEscape(contentType),
	).Replace(s.DownloadURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jmap download: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, httpError(resp)
	}
	return resp.Body, nil
}

func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	// url.ResolveReference would escape the RFC 6570 braces of the templates.
	if strings.HasPrefix(ref, "/") && !strings.HasPrefix(ref, "//") {
		return b.Scheme + "://" + b.Host + ref
	}
	return ref
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
