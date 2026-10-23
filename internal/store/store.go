// Package store persists the bridge state in SQLite, with secrets encrypted by AES-GCM.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a record does not exist or has expired.
var ErrNotFound = errors.New("not found")

// Store is the bridge database.
type Store struct {
	db     *sql.DB
	aead   cipher.AEAD
	master []byte
}

// Open opens (and creates or migrates) the database in dir with the given master key.
func Open(dir string, master []byte) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "jmap-mcp.db")
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600); err == nil {
		f.Close()
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, master: master}
	block, err := aes.NewCipher(s.Key("db-encryption"))
	if err != nil {
		return nil, err
	}
	if s.aead, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for i, f := range files {
		if i < version {
			continue
		}
		b, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(b)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", f, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Key derives a 32-byte purpose-specific key from the master key.
func (s *Store) Key(purpose string) []byte {
	k, err := hkdf.Key(sha256.New, s.master, nil, "jmap-mcp "+purpose, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// Hash returns a keyed hash of a secret, used to store issued tokens and codes.
func (s *Store) Hash(secret string) string {
	m := hmac.New(sha256.New, s.Key("token-hash"))
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

// Seal encrypts v as JSON, bound to aad.
func (s *Store) Seal(aad string, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, b, []byte(aad)), nil
}

// Unseal decrypts what Seal produced with the same aad.
func (s *Store) Unseal(aad string, data []byte, v any) error {
	n := s.aead.NonceSize()
	if len(data) < n {
		return errors.New("store: ciphertext too short")
	}
	b, err := s.aead.Open(nil, data[:n], data[n:], []byte(aad))
	if err != nil {
		return fmt.Errorf("store: cannot decrypt (was the master key replaced?): %w", err)
	}
	return json.Unmarshal(b, v)
}

// RandomToken returns a URL-safe random string with prefix.
func RandomToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func now() int64 { return time.Now().Unix() }

// Purge deletes expired codes, requests and tokens.
func (s *Store) Purge(ctx context.Context) error {
	t := now()
	for _, q := range []string{
		"DELETE FROM auth_requests WHERE expires_at < ?",
		"DELETE FROM auth_codes WHERE expires_at < ?",
		"DELETE FROM tokens WHERE expires_at < ?",
	} {
		if _, err := s.db.ExecContext(ctx, q, t); err != nil {
			return err
		}
	}
	return nil
}

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }
