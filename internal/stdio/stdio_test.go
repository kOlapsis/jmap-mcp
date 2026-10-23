package stdio

import (
	"strings"
	"testing"
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
