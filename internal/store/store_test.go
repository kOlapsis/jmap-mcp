package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/oauth2"

	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	key, _, err := MasterKey(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestMasterKeyFile(t *testing.T) {
	dir := t.TempDir()
	k1, src, err := MasterKey(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil || fi.Mode().Perm() != 0o600 || src != filepath.Join(dir, "master.key") {
		t.Fatalf("key file: %v %v %s", err, fi, src)
	}
	k2, _, _ := MasterKey(dir, true)
	if string(k1) != string(k2) || len(k1) != 32 {
		t.Fatal("an existing key file must win over the keyring")
	}
}

func TestSealBindsAAD(t *testing.T) {
	s, _ := open(t)
	b, err := s.Seal("a", map[string]string{"k": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := s.Unseal("a", b, &out); err != nil || out["k"] != "secret" {
		t.Fatalf("unseal: %v %v", err, out)
	}
	if s.Unseal("b", b, &out) == nil {
		t.Fatal("ciphertext moved to another record must not decrypt")
	}
	if h := s.Hash("x"); h != s.Hash("x") || h == s.Hash("y") || s.Key("a") == nil {
		t.Fatal("hash")
	}
}

func TestAccounts(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	uid, err := s.UpsertUser(ctx, "", LocalUser)
	if err != nil || uid != LocalUser {
		t.Fatalf("user: %v %s", err, uid)
	}
	if again, _ := s.UpsertUser(ctx, "", LocalUser); again != uid {
		t.Fatal("user not unique")
	}
	tok := &oauth2.Token{AccessToken: "access-token-one", RefreshToken: "refresh-token-one"}
	id, err := s.SaveAccount(ctx, &Account{UserID: uid, Email: "Alice@Example.com", Issuer: "https://i", SessionURL: "https://s", Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if id2, _ := s.SaveAccount(ctx, &Account{UserID: uid, Email: "alice@example.com", Issuer: "https://i", SessionURL: "https://s", Token: tok}); id2 != id {
		t.Fatal("reconnecting must replace the account")
	}
	if _, err := s.SaveAccount(ctx, &Account{UserID: uid, Email: "bob@example.com", Issuer: "https://i", SessionURL: "https://s", Token: tok}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateToken(ctx, id, &oauth2.Token{AccessToken: "access-token-two", RefreshToken: "refresh-token-one"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDefault(ctx, uid, "BOB@example.com"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.SetDefault(ctx, uid, "nobody@example.com"), ErrNotFound) {
		t.Fatal("unknown default accepted")
	}
	accts, err := s.Accounts(ctx, uid)
	if err != nil || len(accts) != 2 || accts[0].Token.AccessToken != "access-token-two" || accts[0].Default || !accts[1].Default {
		t.Fatalf("accounts: %v %+v", err, accts)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "jmap-mcp.db"))
	if len(raw) > 0 && (contains(raw, "access-token-two") || contains(raw, "refresh-token-one")) {
		t.Fatal("token stored in clear")
	}
}

func TestHost(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if _, err := s.Host(ctx, "https://i", "web"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	h := &Host{Meta: &mailauth.Meta{}, Registration: &mailauth.Registration{ClientID: "c", ClientSecret: "sec", Static: true}}
	h.Meta.Issuer = "https://i"
	if err := s.SaveHost(ctx, "https://i", "web", h); err != nil {
		t.Fatal(err)
	}
	got, err := s.Host(ctx, "https://i", "web")
	if err != nil || got.Registration.ClientSecret != "sec" || got.Meta.Issuer != "https://i" {
		t.Fatalf("host: %v %+v", err, got)
	}
	if l, _ := s.StaticHosts(ctx, "web"); len(l) != 1 {
		t.Fatalf("static hosts: %v", l)
	}
}

func contains(b []byte, s string) bool {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return true
		}
	}
	return false
}
