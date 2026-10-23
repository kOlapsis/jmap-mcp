package testenv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Exchange is one recorded HTTP exchange with a JMAP server.
type Exchange struct {
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Status      int             `json:"status"`
	ContentType string          `json:"content_type,omitempty"`
	Request     json.RawMessage `json:"request,omitempty"`
	Response    json.RawMessage `json:"response,omitempty"`
	Body        []byte          `json:"body,omitempty"`
}

// Replay serves the exchanges recorded in dir and returns the session URL.
// API calls are matched on their method calls, so a test must repeat the recorded calls.
func Replay(t testing.TB, dir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	var exs []Exchange
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var ex Exchange
		if err := json.Unmarshal(b, &ex); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		exs = append(exs, ex)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, ex := range exs {
			if ex.Method != r.Method || ex.Path != r.URL.Path || (ex.Request != nil && callsKey(ex.Request) != callsKey(body)) {
				continue
			}
			w.Header().Set("Content-Type", ex.ContentType)
			w.WriteHeader(ex.Status)
			if ex.Response != nil {
				_, _ = w.Write([]byte(strings.ReplaceAll(string(ex.Response), "https://"+Host, srv.URL)))
			} else {
				_, _ = w.Write(ex.Body)
			}
			return
		}
		t.Errorf("replay: no recorded exchange for %s %s %s", r.Method, r.URL.Path, body)
		http.Error(w, "not recorded", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/jmap/session"
}

func callsKey(body json.RawMessage) string {
	var req struct {
		Using []string        `json:"using"`
		Calls json.RawMessage `json:"methodCalls"`
	}
	_ = json.Unmarshal(body, &req)
	slices.Sort(req.Using)
	b, _ := json.Marshal(req)
	return string(b)
}
