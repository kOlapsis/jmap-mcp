package httpd

import (
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/kOlapsis/jmap-mcp/internal/mailauth"
	"github.com/kOlapsis/jmap-mcp/internal/store"
)

var pages = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · jmap-mcp</title>
<style>
:root{color-scheme:light dark;--fg:#1d2330;--muted:#5b6475;--bg:#f6f7f9;--card:#fff;--line:#d9dde4;--accent:#2b59c3;--err:#b42318}
@media (prefers-color-scheme:dark){:root{--fg:#e7e9ee;--muted:#a3abba;--bg:#14171c;--card:#1d2128;--line:#343a45;--accent:#7aa2ff;--err:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:30rem;margin:8vh auto;padding:0 1rem}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.5rem}
h1{font-size:1.3rem;margin:0 0 .75rem}p{margin:.5rem 0}.muted{color:var(--muted);font-size:.9rem}.err{color:var(--err)}
label{display:block;font-weight:600;margin:1rem 0 .25rem}input,select{width:100%;padding:.6rem .7rem;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit}
.row{display:flex;gap:.5rem;margin-top:1.25rem}button{flex:1;padding:.65rem;border-radius:8px;border:1px solid var(--line);background:transparent;color:inherit;font:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}code{word-break:break-all}dl{margin:.75rem 0}dt{font-weight:600}dd{margin:0 0 .5rem}
</style></head><body><main><div class="card">{{end}}
{{define "foot"}}</div><p class="muted">jmap-mcp · <a href="https://github.com/kOlapsis/jmap-mcp">source</a></p></main></body></html>{{end}}

{{define "page"}}{{template "head" .}}<h1>{{.Title}}</h1><p>{{.Message}}</p>
{{if .Details}}<dl>{{range $k, $v := .Details}}<dt>{{$k}}</dt><dd><code>{{$v}}</code></dd>{{end}}</dl>{{end}}{{template "foot"}}{{end}}

{{define "login"}}{{template "head" .}}<h1>Connect your mailbox</h1>
<p><strong>{{.Client}}</strong> asks to read and organize your email through this bridge{{if .Host}} (it will receive access at <code>{{.Host}}</code>){{end}}.</p>
<p class="muted">Enter your email address. You will then sign in on your own mail server's page; your password never goes through this bridge or the assistant.</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="authorize"><input type="hidden" name="request" value="{{.Request}}">
<label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required autofocus value="{{.Email}}">
<div class="row"><button type="submit" name="action" value="deny">Deny</button><button class="primary" type="submit" name="action" value="allow">Continue</button></div>
</form>{{template "foot"}}{{end}}

{{define "admin"}}{{template "head" .}}<h1>Static mail-server clients</h1>
<p>Use this page only when a mail server refuses dynamic client registration. Declare an OAuth client on the mail server with this redirect address, then enter its credentials below.</p>
<dl><dt>Redirect address</dt><dd><code>{{.Callback}}</code></dd></dl>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}{{if .Message}}<p>{{.Message}}</p>{{end}}
{{if .Hosts}}<p class="muted">Configured: {{range .Hosts}}<code>{{.}}</code> {{end}}</p>{{end}}
<form method="post" action="admin">
<label for="server">Mail server</label><input id="server" name="server" required placeholder="user@example.com or https://mail.example.com">
<label for="client_id">Client ID</label><input id="client_id" name="client_id" required autocomplete="off">
<label for="client_secret">Client secret (empty for a public client)</label><input id="client_secret" name="client_secret" type="password" autocomplete="off">
<label for="auth_method">Client authentication</label><select id="auth_method" name="auth_method">
<option value="client_secret_basic">client_secret_basic</option><option value="client_secret_post">client_secret_post</option><option value="none">none (public client with PKCE)</option></select>
<div class="row"><button class="primary" type="submit">Save</button></div></form>{{template "foot"}}{{end}}
`))

func (s *Server) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("rendering page", "page", name, "err", err)
	}
}

func (s *Server) page(w http.ResponseWriter, status int, title, msg string, details map[string]string) {
	s.render(w, status, "page", map[string]any{"Title": title, "Message": msg, "Details": details})
}

func (s *Server) loginPage(w http.ResponseWriter, id string, p *pending, errMsg string) {
	host := ""
	if u, err := url.Parse(p.RedirectURI); err == nil {
		host = u.Host
		if host == "" {
			host = u.Scheme + ":"
		}
	}
	name := p.ClientName
	if name == "" {
		name = "An application"
	}
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusBadRequest
	}
	s.render(w, status, "login", map[string]any{"Title": "Connect your mailbox", "Client": name, "Host": host, "Request": id, "Error": errMsg, "Email": p.Email})
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.page(w, http.StatusOK, "jmap-mcp", "This is an MCP server giving AI assistants access to JMAP mailboxes. Add its MCP address to your assistant; you will be asked to sign in with your mail account.",
			map[string]string{"MCP address": s.resource(r)})
	})).ServeHTTP(w, r)
}

func adminToken(st *store.Store) string {
	return base64.RawURLEncoding.EncodeToString(st.Key("admin-page"))[:32]
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	_, pass, ok := r.BasicAuth()
	if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(s.AdminToken())) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="jmap-mcp admin", charset="UTF-8"`)
		http.Error(w, "the admin token is printed by: jmap-mcp admin-token", http.StatusUnauthorized)
		return
	}
	callback := s.base(r) + "/callback"
	data := map[string]any{"Title": "Admin", "Callback": callback}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		if err := s.saveStatic(r, callback); err != nil {
			data["Error"], status = err.Error(), http.StatusBadRequest
		} else {
			data["Message"] = "Saved."
		}
	}
	data["Hosts"], _ = s.st.StaticHosts(r.Context(), hostKind)
	s.render(w, status, "admin", data)
}

func (s *Server) saveStatic(r *http.Request, callback string) error {
	reg := &mailauth.Registration{ClientID: strings.TrimSpace(r.PostFormValue("client_id")), ClientSecret: r.PostFormValue("client_secret"),
		AuthMethod: r.PostFormValue("auth_method"), RedirectURIs: []string{callback}}
	meta, err := s.env.StaticClient(r.Context(), strings.TrimSpace(r.PostFormValue("server")), reg)
	if err != nil {
		return err
	}
	return s.st.SaveHost(r.Context(), meta.Issuer, hostKind, &store.Host{Meta: meta, Registration: reg})
}
