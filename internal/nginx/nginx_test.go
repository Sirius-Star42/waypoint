package nginx

import (
	"strings"
	"testing"
)

func loadBasic(t *testing.T) *Config {
	t.Helper()
	cfg, err := fromFS(osFS{}, "testdata/basic/nginx.conf", "test")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestParseIncludesAndUpstreams(t *testing.T) {
	cfg := loadBasic(t)
	if len(cfg.Files) != 4 {
		t.Errorf("files = %v, want main + 3 includes", cfg.Files)
	}
	if len(cfg.Notes) != 1 || !strings.Contains(cfg.Notes[0], "mime.types") {
		t.Errorf("notes = %v, want one note about the missing mime.types", cfg.Notes)
	}
	if got := len(cfg.Servers); got != 7 {
		t.Fatalf("servers = %d, want 7", got)
	}
	if eps := cfg.Upstreams["backend"]; len(eps) != 2 || eps[0].String() != "127.0.0.1:8080" {
		t.Errorf("upstream backend = %v", eps)
	}
	if len(cfg.Conflicts) != 1 || cfg.Conflicts[0].Name != "api.example.com" || cfg.Conflicts[0].Port != 443 {
		t.Errorf("conflicts = %+v", cfg.Conflicts)
	}
}

func TestRoute(t *testing.T) {
	cfg := loadBasic(t)
	tests := []struct {
		host   string
		port   int
		path   string
		server string // first server_name
		loc    string // location as written, "" for server-level return
		target string
	}{
		{"api.example.com", 443, "/", "api.example.com", "/", "http://backend"},
		{"api.example.com", 443, "/users/1", "api.example.com", "/", "http://backend"},
		{"API.example.com.", 443, "/static/app.js", "api.example.com", "/static/", "/srv/api/static/"},
		{"api.example.com", 443, "/static/logo.png", "api.example.com", "~* \\.(png|jpg)$", "/srv/images"},
		{"api.example.com", 443, "/admin/logo.png", "api.example.com", "^~ /admin/", "http://127.0.0.1:9000/"},
		{"api.example.com", 443, "/health", "api.example.com", "= /health", `return 200 "ok"`},
		{"api.example.com", 443, "/healthz", "api.example.com", "/", "http://backend"},
		{"api.example.com", 443, "/v2/ws/chat", "api.example.com", "~ ^/v2/ws", "http://127.0.0.1:8090"},
		{"api.example.com", 443, "/v2/items", "api.example.com", "/v2/", "http://unix:/run/api.sock:/"},
		{"shop.example.com", 443, "/", "*.example.com", "/", "http://$upstream_host"},
		{"www.example.net", 443, "/", "www.example.*", "/", "unix:/run/php/php8.2-fpm.sock"},
		{"bob.users.example.org", 443, "/", `~^(?<user>[a-z]+)\.users\.example\.org$`, "/", "http://127.0.0.1:7000"},
		{"unknown.test", 443, "/", "api.example.com", "/", "http://backend"}, // first server on :443
		{"anything", 80, "/x", "_", "", ""},
		{"static.local", 8080, "/index.html", "static.local", "/", "/var/www/default"},
	}
	for _, tt := range tests {
		m := cfg.Route(tt.host, tt.port, tt.path)
		if m == nil {
			t.Errorf("%s:%d%s: no match", tt.host, tt.port, tt.path)
			continue
		}
		if m.Server.Names[0] != tt.server {
			t.Errorf("%s:%d%s: server %q, want %q", tt.host, tt.port, tt.path, m.Server.Names[0], tt.server)
			continue
		}
		if tt.loc == "" {
			if m.Location != nil || m.Server.Return == nil {
				t.Errorf("%s:%d%s: want server-level return", tt.host, tt.port, tt.path)
			}
			continue
		}
		if m.Location == nil {
			t.Errorf("%s:%d%s: no location", tt.host, tt.port, tt.path)
			continue
		}
		if m.Location.String() != tt.loc || m.Location.Target() != tt.target {
			t.Errorf("%s:%d%s: location %q → %q, want %q → %q", tt.host, tt.port, tt.path,
				m.Location.String(), m.Location.Target(), tt.loc, tt.target)
		}
	}
	if m := cfg.Route("api.example.com", 9999, "/"); m != nil {
		t.Errorf("port without listener should not match, got %v", m.Server.Names)
	}
}

func TestSplitDump(t *testing.T) {
	out := `# configuration file /etc/nginx/nginx.conf:
http { include /etc/nginx/sites-enabled/*; }

# configuration file /etc/nginx/sites-enabled/a:
server { listen 81; server_name a.test; location / { proxy_pass http://127.0.0.1:5000; } }
`
	files, main := splitDump(out)
	if main != "/etc/nginx/nginx.conf" || len(files) != 2 {
		t.Fatalf("main=%q files=%d", main, len(files))
	}
	cfg, err := fromFS(files, main, "nginx -T")
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Route("a.test", 81, "/")
	if m == nil || m.Location.Upstream.Endpoints[0].String() != "127.0.0.1:5000" {
		t.Fatalf("route through dump failed: %+v", m)
	}
	if m.Server.Pos != "/etc/nginx/sites-enabled/a:1" {
		t.Errorf("line numbers must match the original file, got %s", m.Server.Pos)
	}
}

func TestLexer(t *testing.T) {
	toks, err := lex(`set $a "x;y"; rewrite ^/(.*)$ /${a}/$1 break; # comment { ignored
add_header X 'it\'s';`)
	if err != nil {
		t.Fatal(err)
	}
	var words []string
	for _, tk := range toks {
		words = append(words, tk.text)
	}
	got := strings.Join(words, "|")
	want := `set|$a|x;y|;|rewrite|^/(.*)$|/${a}/$1|break|;|add_header|X|it's|;`
	if got != want {
		t.Errorf("tokens\n got %s\nwant %s", got, want)
	}
}

func TestParseErrors(t *testing.T) {
	for _, src := range []string{"http {", "server }", `x "unterminated`} {
		if _, _, _, err := Parse(dumpFS{"/n.conf": src}, "/n.conf"); err == nil {
			t.Errorf("%q: want error", src)
		}
	}
}
