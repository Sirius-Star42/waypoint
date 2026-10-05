package diagnosis

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/collector/docker"
	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/runner"
)

func testEnv(t *testing.T, snap *docker.Snapshot) *Env {
	t.Helper()
	e := NewEnv(context.Background(), runner.Fake{}, time.Second, t.TempDir())
	e.dockerOnce.Do(func() {})
	e.docker = snap
	e.sdOnce.Do(func() {})
	return e
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in, host, scheme, path string
		port                   int
		given                  bool
	}{
		{"8080", "localhost", "", "/", 8080, true},
		{":3000", "localhost", "", "/", 3000, true},
		{"localhost:5432", "localhost", "", "/", 5432, true},
		{"api.example.com", "api.example.com", "", "/", 80, false},
		{"https://example.com/api/users?id=1", "example.com", "https", "/api/users?id=1", 443, false},
		{"http://[::1]:8080/x", "::1", "http", "/x", 8080, true},
	}
	for _, tt := range tests {
		got, err := ParseTarget(tt.in)
		if err != nil {
			t.Errorf("%s: %v", tt.in, err)
			continue
		}
		if got.Host != tt.host || got.Port != tt.port || got.Scheme != tt.scheme || got.Path != tt.path || got.PortGiven != tt.given {
			t.Errorf("%s: got %+v", tt.in, got)
		}
	}
	for _, bad := range []string{"", "0", "70000", "ftp://x", "http://:80"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestLocalhostInsideContainer(t *testing.T) {
	api := &docker.Container{Name: "shop-api-1", Service: "api", Project: "shop", Status: "restarting", RestartCount: 5,
		Env: map[string]string{"DATABASE_URL": "postgres://app:secret@localhost:5432/app"}}
	pg := &docker.Container{Name: "shop-postgres-1", Service: "postgres", Project: "shop", Status: "running", Exposed: []int{5432}}
	e := testEnv(t, &docker.Snapshot{Containers: []*docker.Container{api, pg}})

	p := &Probe{Host: "localhost", Port: 8080, Container: api, TCP: network.Result{Class: network.Reset}}
	e.attachCompose(p, 0)
	if len(p.Deps) != 1 || p.Deps[0].EnvKey != "DATABASE_URL" {
		t.Fatalf("deps = %+v", p.Deps)
	}
	root, _ := Root(e.Analyze(p))
	if root == nil || !strings.Contains(root.Title, "localhost is the container itself") {
		t.Fatalf("root = %+v", root)
	}
	if root.Confidence < 0.9 {
		t.Errorf("crashing container should raise confidence, got %v", root.Confidence)
	}
	fix := root.Fixes[0].Command
	if fix != "DATABASE_URL=postgres://app:***@shop-postgres-1:5432/app" && fix != "DATABASE_URL=postgres://app:***@postgres:5432/app" {
		t.Errorf("fix = %q", fix)
	}
	for _, ev := range root.Evidence {
		if strings.Contains(ev.Text, "secret") {
			t.Errorf("password leaked in evidence: %s", ev.Text)
		}
	}
}

func TestDependencyIsRootCause(t *testing.T) {
	api := &docker.Container{Name: "api", Service: "api", Project: "p", Status: "running",
		Env: map[string]string{"REDIS_URL": "redis://redis:6379"}, Networks: map[string][]string{"p_default": {"api"}}}
	redis := &docker.Container{Name: "p-redis-1", Service: "redis", Project: "p", Status: "exited", ExitCode: 137}
	e := testEnv(t, &docker.Snapshot{Containers: []*docker.Container{api, redis}})
	e.Runner = runner.Fake{Err: map[string]error{}}
	p := &Probe{Host: "localhost", Port: 8080, Container: api, TCP: network.Result{Class: network.OK},
		HTTP: &network.HTTPResult{Result: network.Result{Class: network.OK}, Status: 500}}
	e.attachCompose(p, 0)
	root, others := Root(e.Analyze(p))
	if root == nil || !strings.Contains(root.Title, "redis is not running") {
		t.Fatalf("root = %+v", root)
	}
	if !strings.Contains(root.Detail, "137") {
		t.Errorf("detail should explain exit 137: %q", root.Detail)
	}
	if len(others) != 1 || !strings.Contains(others[0].Title, "answers HTTP 500") {
		t.Errorf("api's 500 should be a side effect, got %+v", others)
	}
}

func TestWrongPort(t *testing.T) {
	api := &docker.Container{Name: "api", Status: "running", Exposed: []int{8080}}
	e := testEnv(t, &docker.Snapshot{Containers: []*docker.Container{api}})
	p := &Probe{Host: "api", Port: 3000, Container: api, ContainerPort: 3000, TCP: network.Result{Class: network.Refused, Err: "connection refused"}}
	f := e.rule(p)
	if f == nil || !strings.Contains(f.Title, "container listens on 8080") {
		t.Fatalf("got %+v", f)
	}
}

func TestDifferentDockerNetwork(t *testing.T) {
	ng := &docker.Container{Name: "web-nginx-1", Service: "nginx", Status: "running", Networks: map[string][]string{"web_default": {"nginx"}}}
	api := &docker.Container{Name: "api", Status: "running", Networks: map[string][]string{"bridge": {"api"}}}
	e := testEnv(t, &docker.Snapshot{Containers: []*docker.Container{ng, api}})
	p := &Probe{Host: "api", Port: 8080, Via: ng, TCP: network.Result{Class: network.NoSuchHost}}
	f := e.rule(p)
	if f == nil || !strings.Contains(f.Title, "not on the same Docker network") {
		t.Fatalf("got %+v", f)
	}
	if f.Fixes[0].Command != "docker network connect web_default api" {
		t.Errorf("fix = %q", f.Fixes[0].Command)
	}
}

func TestDirectHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	tgt, _ := ParseTarget("127.0.0.1:" + port)
	e := testEnv(t, nil)
	r := e.Diagnose(tgt)
	if !r.OK() || !strings.Contains(r.Summary, "HTTP 204") {
		t.Fatalf("report = %+v root=%+v", r, r.Root)
	}
}

func TestDirectResetAfterConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	tgt, _ := ParseTarget("127.0.0.1:" + port)
	r := testEnv(t, nil).Diagnose(tgt)
	if r.OK() || !strings.Contains(r.Root.Title, "doesn't answer HTTP") {
		t.Fatalf("root = %+v", r.Root)
	}
}

func TestTraceThroughNginx(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer app.Close()
	_, appPort, _ := net.SplitHostPort(app.Listener.Addr().String())

	// Stand-in for nginx: answers 502 on its own port.
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }))
	defer front.Close()
	_, frontPort, _ := net.SplitHostPort(front.Listener.Addr().String())

	dir := t.TempDir()
	conf := `http {
  server { listen ` + frontPort + `; server_name shop.test;
    location / { proxy_pass http://127.0.0.1:` + appPort + `; }
    location /api/ { proxy_pass http://127.0.0.1:1; }
    location /assets/ { root ` + filepath.Join(dir, "missing") + `; }
  }
}`
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(conf), 0o644)
	e := testEnv(t, nil)
	e.NginxPath = filepath.Join(dir, "nginx.conf")

	tgt, _ := ParseTarget("http://localhost:" + frontPort + "/api/users")
	r := e.Diagnose(tgt)
	if r.OK() || !strings.Contains(r.Root.Title, "nothing is listening on 127.0.0.1:1") {
		t.Fatalf("root = %+v", r.Root)
	}
	var texts []string
	for _, s := range r.Steps {
		texts = append(texts, s.Text)
	}
	joined := strings.Join(texts, "|")
	for _, want := range []string{"server shop.test", "location /api/", "proxy_pass http://127.0.0.1:1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("steps %q missing %q", joined, want)
		}
	}

	tgt, _ = ParseTarget("http://localhost:" + frontPort + "/")
	r = e.Diagnose(tgt)
	if r.OK() || !strings.Contains(r.Root.Title, "nginx returns 502") {
		t.Fatalf("upstream up but nginx 502: root = %+v", r.Root)
	}

	m, err := e.Map()
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, f := range m.Issues {
		titles = append(titles, f.Title)
	}
	all := strings.Join(titles, "\n")
	if !strings.Contains(all, "/api/ → nothing is listening") || !strings.Contains(all, "missing doesn't exist") {
		t.Errorf("map issues:\n%s", all)
	}
	if strings.Contains(all, "location / ") || strings.Contains(all, "shop.test / →") {
		t.Errorf("the working route should not be an issue:\n%s", all)
	}
}

func TestRedact(t *testing.T) {
	if got := redact("postgres://u:p4ss@db:5432/x"); got != "postgres://u:***@db:5432/x" {
		t.Errorf("got %q", got)
	}
	if got := redact("redis://redis:6379"); got != "redis://redis:6379" {
		t.Errorf("got %q", got)
	}
}

func TestURLHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://u:p@db/app": "db:5432",
		"redis://cache:6380":    "cache:6380",
		"api:8080":              "api:8080",
		"hello world":           ":0",
		"/var/run/x.sock":       ":0",
	} {
		h, p := urlHostPort(in)
		if got := h + ":" + strconv.Itoa(p); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestRootPrefersRealFailureOverDeeperOne(t *testing.T) {
	stopped := &Finding{Title: "nginx stopped", Depth: 0, Confidence: 0.9}
	crash := &Finding{Title: "api crash loop", Depth: 1, Confidence: 0.9, Symptom: true}
	db := &Finding{Title: "postgres down", Depth: 2, Confidence: 0.9}
	if root, _ := Root([]*Finding{db, crash, stopped}); root != stopped {
		t.Errorf("a stopped front door is the root cause, got %q", root.Title)
	}
	if root, others := Root([]*Finding{crash, db}); root != db || len(others) != 1 {
		t.Errorf("a crash loop defers to its failing dependency, got %q", root.Title)
	}
	if root, _ := Root([]*Finding{crash}); root != crash {
		t.Errorf("a lone symptom is still reported, got %q", root.Title)
	}
}
