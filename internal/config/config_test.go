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

func TestStatelessFlag(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		t.Setenv(EnvPrefix+"STATELESS", "false")
		cfg, err := Parse([]string{"serve"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Stateless {
			t.Fatal("Stateless = true, want false by default")
		}
	})

	t.Run("enabled by flag", func(t *testing.T) {
		cfg, err := Parse([]string{"serve", "--stateless"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Stateless {
			t.Fatal("Stateless = false, want true")
		}
	})

	t.Run("enabled by environment", func(t *testing.T) {
		t.Setenv(EnvPrefix+"STATELESS", "true")
		cfg, err := Parse([]string{"serve"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Stateless {
			t.Fatal("Stateless = false, want true from environment")
		}
	})
}
