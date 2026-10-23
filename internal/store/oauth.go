package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Client is an MCP client registered at the bridge (RFC 7591).
type Client struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	AuthMethod   string   `json:"token_endpoint_auth_method"`
	SecretHash   string   `json:"-"`
}

// SaveClient stores a new client.
func (s *Store) SaveClient(ctx context.Context, c *Client) error {
	meta, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO mcp_clients (client_id, secret_hash, metadata, created_at) VALUES (?, ?, ?, ?)",
		c.ClientID, c.SecretHash, string(meta), now())
	return err
}

// Client returns a registered client.
func (s *Store) Client(ctx context.Context, id string) (*Client, error) {
	var hash, meta string
	err := s.db.QueryRowContext(ctx, "SELECT secret_hash, metadata FROM mcp_clients WHERE client_id = ?", id).Scan(&hash, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := &Client{}
	if err := json.Unmarshal([]byte(meta), c); err != nil {
		return nil, err
	}
	c.SecretHash = hash
	return c, nil
}

// SaveAuthRequest stores (or replaces) an encrypted pending authorization request.
func (s *Store) SaveAuthRequest(ctx context.Context, id string, v any, ttl time.Duration) error {
	data, err := s.Seal("authreq:"+id, v)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO auth_requests (id, data, expires_at) VALUES (?, ?, ?) ON CONFLICT (id) DO UPDATE SET data = excluded.data",
		id, data, time.Now().Add(ttl).Unix())
	return err
}

// AuthRequest loads a pending authorization request; with consume it is deleted.
func (s *Store) AuthRequest(ctx context.Context, id string, v any, consume bool) error {
	var data []byte
	err := s.db.QueryRowContext(ctx, "SELECT data FROM auth_requests WHERE id = ? AND expires_at >= ?", id, now()).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if consume {
		res, err := s.db.ExecContext(ctx, "DELETE FROM auth_requests WHERE id = ?", id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	return s.Unseal("authreq:"+id, data, v)
}

// Grant is what an authorization code or token stands for.
type Grant struct {
	UserID        string `json:"user_id"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri,omitempty"`
	CodeChallenge string `json:"code_challenge,omitempty"`
	Resource      string `json:"resource"`
	Scope         string `json:"scope"`
	ExpiresAt     int64  `json:"-"`
	Family        string `json:"-"`
}

// SaveCode stores an authorization code by its hash.
func (s *Store) SaveCode(ctx context.Context, code string, g *Grant, ttl time.Duration) error {
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO auth_codes (code_hash, user_id, data, expires_at) VALUES (?, ?, ?, ?)",
		s.Hash(code), g.UserID, string(data), time.Now().Add(ttl).Unix())
	return err
}

// ConsumeCode returns and deletes an authorization code; a code works once.
func (s *Store) ConsumeCode(ctx context.Context, code string) (*Grant, error) {
	h := s.Hash(code)
	var data string
	var exp int64
	err := s.db.QueryRowContext(ctx, "DELETE FROM auth_codes WHERE code_hash = ? RETURNING data, expires_at", h).Scan(&data, &exp)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && exp < now()) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g := &Grant{}
	return g, json.Unmarshal([]byte(data), g)
}

// Token kinds.
const (
	AccessToken  = "access"
	RefreshToken = "refresh"
	usedRefresh  = "refresh_used"
)

// SaveToken stores an issued token by its hash.
func (s *Store) SaveToken(ctx context.Context, token, kind string, g *Grant, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO tokens (token_hash, kind, user_id, client_id, resource, scope, family, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		s.Hash(token), kind, g.UserID, g.ClientID, g.Resource, g.Scope, g.Family, time.Now().Add(ttl).Unix())
	return err
}

// Token returns a valid token of the given kind.
func (s *Store) Token(ctx context.Context, token, kind string) (*Grant, error) {
	g := &Grant{}
	err := s.db.QueryRowContext(ctx, "SELECT user_id, client_id, resource, scope, family, expires_at FROM tokens WHERE token_hash = ? AND kind = ? AND expires_at >= ?",
		s.Hash(token), kind, now()).Scan(&g.UserID, &g.ClientID, &g.Resource, &g.Scope, &g.Family, &g.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

// ErrTokenReuse means a rotated refresh token was presented again; its whole family is revoked.
var ErrTokenReuse = errors.New("refresh token reuse")

// RotateRefresh marks a refresh token as used and returns its grant.
// Presenting an already rotated token revokes every token of its family (RFC 9700 §4.14.2).
func (s *Store) RotateRefresh(ctx context.Context, token string) (*Grant, error) {
	h := s.Hash(token)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	g := &Grant{}
	var kind string
	err = tx.QueryRowContext(ctx, "SELECT kind, user_id, client_id, resource, scope, family, expires_at FROM tokens WHERE token_hash = ? AND kind IN (?, ?) AND expires_at >= ?",
		h, RefreshToken, usedRefresh, now()).Scan(&kind, &g.UserID, &g.ClientID, &g.Resource, &g.Scope, &g.Family, &g.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if kind == usedRefresh {
		if _, err := tx.ExecContext(ctx, "DELETE FROM tokens WHERE family = ?", g.Family); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrTokenReuse
	}
	if _, err := tx.ExecContext(ctx, "UPDATE tokens SET kind = ? WHERE token_hash = ?", usedRefresh, h); err != nil {
		return nil, err
	}
	return g, tx.Commit()
}

// RevokeToken deletes a token; revoking a refresh token revokes its whole family.
func (s *Store) RevokeToken(ctx context.Context, token string) error {
	var family, kind string
	err := s.db.QueryRowContext(ctx, "SELECT family, kind FROM tokens WHERE token_hash = ?", s.Hash(token)).Scan(&family, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if kind == AccessToken {
		_, err = s.db.ExecContext(ctx, "DELETE FROM tokens WHERE token_hash = ?", s.Hash(token))
		return err
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM tokens WHERE family = ?", family)
	return err
}

// Account returns one account of a user by id.
func (s *Store) Account(ctx context.Context, userID, accountID string) (*Account, error) {
	accts, err := s.Accounts(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.ID == accountID {
			return a, nil
		}
	}
	return nil, ErrNotFound
}
