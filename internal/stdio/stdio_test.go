package stdio

import (
	"strings"
	"testing"

	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
	"github.com/kOlapsis/jmap-mcp/internal/store"
)

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"report.pdf":       "report.pdf",
		"../../etc/passwd": "passwd",
		`C:\Users\x\a.txt`: "a.txt",
		"":                 "attachment",
		"..":               "attachment",
		"a:b*c?.txt":       "a_b_c_.txt",
		"new\nline.txt":    "new_line.txt",
	} {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
	long := safeName(strings.Repeat("é", 200) + ".pdf")
	if len(long) > 120 || !strings.HasSuffix(long, ".pdf") {
		t.Errorf("long name not shortened: %d bytes", len(long))
	}
}

func TestDeviceFlowAvailable(t *testing.T) {
	withDevice := &mailauth.Meta{DeviceAuthorizationEndpoint: "https://mail.example.test/auth/device"}
	for _, c := range []struct {
		host *store.Host
		want bool
	}{
		{&store.Host{Meta: withDevice, Registration: &mailauth.Registration{GrantTypes: []string{"authorization_code", "refresh_token", mailauth.DeviceGrant}}}, true},
		{&store.Host{Meta: withDevice, Registration: &mailauth.Registration{GrantTypes: []string{"authorization_code", "refresh_token"}}}, false},
		{&store.Host{Meta: withDevice, Registration: &mailauth.Registration{Static: true}}, true},
		{&store.Host{Meta: &mailauth.Meta{}, Registration: &mailauth.Registration{}}, false},
	} {
		if got := deviceFlowAvailable(c.host); got != c.want {
			t.Errorf("deviceFlowAvailable(%+v) = %v, want %v", c.host.Registration, got, c.want)
		}
	}
}
