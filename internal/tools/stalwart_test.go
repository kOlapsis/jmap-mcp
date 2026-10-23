//go:build integration

package tools

import (
	"testing"

	"github.com/kOlapsis/jmap-mcp/internal/testenv"
)

func TestStalwartReadTools(t *testing.T) {
	sw := testenv.Start(t)
	alice := sw.CreateUser(t, "alice", "alice-password-1")
	sw.Seed(t, alice, "alice-password-1", testenv.Fixtures...)
	readScenario(t, &Account{Email: alice, Client: sw.Login(t, alice, "alice-password-1")})
}
