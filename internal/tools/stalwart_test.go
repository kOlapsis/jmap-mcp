//go:build integration

package tools

import (
	"strings"
	"testing"

	"github.com/kOlapsis/jmap-mcp/internal/testenv"
)

func TestStalwartReadTools(t *testing.T) {
	sw := testenv.Start(t)
	alice := sw.CreateUser(t, "alice", "alice-password-1")
	sw.Seed(t, alice, "alice-password-1", testenv.Fixtures...)
	readScenario(t, &Account{Email: alice, Client: sw.Login(t, alice, "alice-password-1")})
}

func TestStalwartWriteTools(t *testing.T) {
	sw := testenv.Start(t)
	alice := sw.CreateUser(t, "alice", "alice-password-1")
	bob := sw.CreateUser(t, "bob", "bob-password-1")
	sw.Seed(t, alice, "alice-password-1", testenv.Fixtures...)
	bobAccount := sw.AccountID(t, bob, "bob-password-1")
	delivered := func(subject string) bool {
		res := sw.JMAP(t, bob, "bob-password-1", []any{[]any{"Email/query", map[string]any{"accountId": bobAccount, "filter": map[string]any{"subject": subject}}, "q"}})
		return !strings.Contains(string(res[0][1]), `"ids":[]`)
	}
	writeScenario(t, &Account{Email: alice, Client: sw.Login(t, alice, "alice-password-1")}, bob, delivered)
}
