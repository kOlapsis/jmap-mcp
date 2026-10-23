package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
)

// LocalUser is the single user of the stdio mode.
const LocalUser = "local"

// UpsertUser returns the id of the user identified by (issuer, subject), creating it if needed.
func (s *Store) UpsertUser(ctx context.Context, issuer, subject string) (string, error) {
	id := RandomToken("u_")
	if issuer == "" && subject == LocalUser {
		id = LocalUser
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO users (id, issuer, subject, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (issuer, subject) DO NOTHING",
		id, issuer, subject, now())
	if err != nil {
		return "", err
	}
	err = s.db.QueryRowContext(ctx, "SELECT id FROM users WHERE issuer = ? AND subject = ?", issuer, subject).Scan(&id)
	return id, err
}

// UserExists reports whether a user id is known.
func (s *Store) UserExists(ctx context.Context, id string) bool {
	var one int
	return s.db.QueryRowContext(ctx, "SELECT 1 FROM users WHERE id = ?", id).Scan(&one) == nil
}

// Host is a discovered authorization server and this bridge's registration there.
type Host struct {
	Meta         *mailauth.Meta
	Registration *mailauth.Registration
}

// Host returns the stored registration for issuer; kind separates loopback and web redirect URIs.
func (s *Store) Host(ctx context.Context, issuer, kind string) (*Host, error) {
	var meta string
	var reg []byte
	err := s.db.QueryRowContext(ctx, "SELECT metadata, registration FROM hosts WHERE issuer = ? AND kind = ?", issuer, kind).Scan(&meta, &reg)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	h := &Host{Meta: &mailauth.Meta{}, Registration: &mailauth.Registration{}}
	if err := json.Unmarshal([]byte(meta), h.Meta); err != nil {
		return nil, err
	}
	return h, s.Unseal("host:"+issuer+":"+kind, reg, h.Registration)
}

// SaveHost stores the metadata and registration of issuer.
func (s *Store) SaveHost(ctx context.Context, issuer, kind string, h *Host) error {
	meta, err := json.Marshal(h.Meta)
	if err != nil {
		return err
	}
	reg, err := s.Seal("host:"+issuer+":"+kind, h.Registration)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO hosts (issuer, kind, metadata, registration, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (issuer, kind) DO UPDATE SET metadata = excluded.metadata, registration = excluded.registration, updated_at = excluded.updated_at`,
		issuer, kind, string(meta), reg, now())
	return err
}

// StaticHosts lists the issuers whose registration was entered by the operator.
func (s *Store) StaticHosts(ctx context.Context, kind string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT issuer FROM hosts WHERE kind = ? ORDER BY issuer", kind)
	if err != nil {
		return nil, err
	}
	var issuers []string
	for rows.Next() {
		var iss string
		if err := rows.Scan(&iss); err != nil {
			rows.Close()
			return nil, err
		}
		issuers = append(issuers, iss)
	}
	rows.Close()
	var out []string
	for _, iss := range issuers {
		if h, err := s.Host(ctx, iss, kind); err == nil && h.Registration.Static {
			out = append(out, iss)
		}
	}
	return out, nil
}

// Account is a connected mail account with its mail-server token.
type Account struct {
	ID         string
	UserID     string
	Email      string
	Issuer     string
	SessionURL string
	Token      *oauth2.Token
	Default    bool
}

// Accounts lists the accounts of a user. Accounts whose token cannot be decrypted are skipped.
func (s *Store) Accounts(ctx context.Context, userID string) ([]*Account, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, email, issuer, session_url, token, is_default FROM accounts WHERE user_id = ? ORDER BY created_at", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a := &Account{UserID: userID, Token: &oauth2.Token{}}
		var tok []byte
		if err := rows.Scan(&a.ID, &a.Email, &a.Issuer, &a.SessionURL, &tok, &a.Default); err != nil {
			return nil, err
		}
		if s.Unseal("account:"+a.ID, tok, a.Token) != nil {
			continue
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SaveAccount creates or replaces the account (user, email) and returns its id.
func (s *Store) SaveAccount(ctx context.Context, a *Account) (string, error) {
	a.Email = normEmail(a.Email)
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM accounts WHERE user_id = ? AND email = ?", a.UserID, a.Email).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		id = RandomToken("a_")
	} else if err != nil {
		return "", err
	}
	tok, err := s.Seal("account:"+id, a.Token)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO accounts (id, user_id, email, issuer, session_url, token, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET issuer = excluded.issuer, session_url = excluded.session_url, token = excluded.token, updated_at = excluded.updated_at`,
		id, a.UserID, a.Email, a.Issuer, a.SessionURL, tok, now(), now())
	return id, err
}

// UpdateToken replaces the stored token of an account after a refresh.
func (s *Store) UpdateToken(ctx context.Context, accountID string, t *oauth2.Token) error {
	tok, err := s.Seal("account:"+accountID, t)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE accounts SET token = ?, updated_at = ? WHERE id = ?", tok, now(), accountID)
	return err
}

// SetDefault marks one account of the user as the default.
func (s *Store) SetDefault(ctx context.Context, userID, email string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE accounts SET is_default = 1 WHERE user_id = ? AND email = ?", userID, normEmail(email))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "UPDATE accounts SET is_default = 0 WHERE user_id = ? AND email != ?", userID, normEmail(email)); err != nil {
		return err
	}
	return tx.Commit()
}
