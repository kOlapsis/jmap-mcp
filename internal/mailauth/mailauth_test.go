package mailauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/oauth2"
)

func idToken(claims map[string]any) *oauth2.Token {
	b, _ := json.Marshal(claims)
	raw := "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
	return (&oauth2.Token{AccessToken: "a"}).WithExtra(map[string]any{"id_token": raw})
}

func TestCheckIDToken(t *testing.T) {
	m := &Meta{}
	m.Issuer = "https://mail.example.com"
	good := map[string]any{"iss": "https://mail.example.com", "aud": "client", "nonce": "n1"}
	if err := CheckIDToken(m, idToken(good), "client", "n1"); err != nil {
		t.Fatal(err)
	}
	if err := CheckIDToken(m, &oauth2.Token{AccessToken: "a"}, "client", "n1"); err != nil {
		t.Fatal("a response without id_token must pass:", err)
	}
	for name, claims := range map[string]map[string]any{
		"nonce":    {"iss": "https://mail.example.com", "aud": "client", "nonce": "other"},
		"issuer":   {"iss": "https://evil.example", "aud": "client", "nonce": "n1"},
		"audience": {"iss": "https://mail.example.com", "aud": []string{"someone"}, "nonce": "n1"},
	} {
		if CheckIDToken(m, idToken(claims), "client", "n1") == nil {
			t.Errorf("%s mismatch accepted", name)
		}
	}
	if err := CheckIDToken(m, idToken(map[string]any{"iss": "https://mail.example.com", "aud": []string{"x", "client"}, "nonce": "n1"}), "client", "n1"); err != nil {
		t.Fatal(err)
	}
}

func TestScopes(t *testing.T) {
	m := &Meta{}
	m.ScopesSupported = []string{"openid", MailScope, "offline_access"}
	if s := Scopes(m); len(s) != 2 || s[0] != MailScope || s[1] != "offline_access" {
		t.Fatalf("scopes %v", s)
	}
	if CheckIssuer(m, "") != nil {
		t.Fatal("iss is optional when not advertised")
	}
	m.Issuer, m.AuthorizationResponseIssParameterSupported = "https://a", true
	if CheckIssuer(m, "") == nil || CheckIssuer(m, "https://b") == nil || CheckIssuer(m, "https://a/") != nil {
		t.Fatal("iss checks")
	}
}
