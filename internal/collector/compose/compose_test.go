package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	p, err := Load("testdata/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ng := p.Services["nginx"]
	if len(ng.Ports) != 2 || ng.Ports[1] != (Port{Host: 443, Container: 443}) {
		t.Errorf("nginx ports = %v", ng.Ports)
	}
	api := p.Services["api"]
	if api.Env["WORKERS"] != "4" || api.Env["REDIS_URL"] != "redis://redis:6379" {
		t.Errorf("api env = %v", api.Env)
	}
	if len(api.DependsOn) != 2 || api.DependsOn[0] != "postgres" {
		t.Errorf("api depends_on = %v", api.DependsOn)
	}
	if p.Services["postgres"].Env["POSTGRES_PASSWORD"] != "secret" {
		t.Error("list-style environment not parsed")
	}
	if s := p.ByHostPort(8080); s == nil || s.Name != "api" {
		t.Errorf("ByHostPort(8080) = %v", s)
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a", "b")
	os.MkdirAll(sub, 0o755)
	os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}"), 0o644)
	if got := Find(sub); got != filepath.Join(dir, "docker-compose.yml") {
		t.Errorf("Find = %q", got)
	}
}
