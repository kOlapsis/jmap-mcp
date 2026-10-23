package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
)

const keyringService = "jmap-mcp"

// MasterKey loads the master key of dir or generates it on first start.
// With useKeyring, a key is kept in the OS keyring when one is available;
// otherwise, or when a key file already exists, it lives in dir/master.key (mode 0600).
func MasterKey(dir string, useKeyring bool) (key []byte, source string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "master.key")
	if b, err := os.ReadFile(path); err == nil {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, "", fmt.Errorf("invalid master key in %s", path)
		}
		return k, path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	abs, _ := filepath.Abs(dir)
	if useKeyring {
		if v, err := keyring.Get(keyringService, abs); err == nil {
			if k, err := base64.StdEncoding.DecodeString(v); err == nil && len(k) == 32 {
				return k, "os keyring", nil
			}
		}
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, "", err
	}
	enc := base64.StdEncoding.EncodeToString(k)
	if useKeyring && keyring.Set(keyringService, abs, enc) == nil {
		return k, "os keyring", nil
	}
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		return nil, "", err
	}
	return k, path, nil
}
