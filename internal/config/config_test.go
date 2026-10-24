package config

import (
	"io"
	"slices"
	"testing"
)

func TestParseFlagsAfterArguments(t *testing.T) {
	dir := t.TempDir()
	c, err := Parse([]string{"client", "add", "alice@example.com", "--client-id", "webui", "--data-dir", dir}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Command != "client" || !slices.Equal(c.Args, []string{"add", "alice@example.com"}) || c.ClientID != "webui" || c.DataDir != dir {
		t.Fatalf("%+v", c)
	}
}
