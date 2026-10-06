package diagnosis

import (
	"strings"
	"testing"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/collector/docker"
	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/collector/process"
)

func TestAppName(t *testing.T) {
	tests := []struct {
		o    process.Owner
		want string
	}{
		{process.Owner{Cmdline: "/usr/bin/python3 /srv/shop/app.py", Cwd: "/srv/shop"}, "shop"},
		{process.Owner{Cmdline: "/opt/billing/bin/server --port 9100", Exe: "/opt/billing/bin/server", Cwd: "/"}, "billing"},
		{process.Owner{Cmdline: "node dist/index.js", Cwd: "/home/deploy"}, "index"},
		{process.Owner{Name: "grafana", Cmdline: "/usr/sbin/grafana server"}, "grafana"},
	}
	for _, tt := range tests {
		if got := appName(&tt.o); got != tt.want {
			t.Errorf("%s: got %q want %q", tt.o.Cmdline, got, tt.want)
		}
	}
}

func TestContainerApps(t *testing.T) {
	old := time.Now().Add(-90 * 24 * time.Hour)
	snap := &docker.Snapshot{Containers: []*docker.Container{
		{ID: "a1", Name: "shop-api-1", Project: "shop", Service: "api", Status: "running", Started: time.Now().Add(-3 * time.Hour),
			Bindings: []docker.Binding{{HostIP: "127.0.0.1", HostPort: 8081, ContainerPort: 8080}}},
		{ID: "a2", Name: "shop-migrate-1", Project: "shop", Service: "migrate", Status: "exited", ExitCode: 0},
		{ID: "a3", Name: "shop-redis-1", Project: "shop", Service: "redis", Status: "exited", ExitCode: 1},
		{ID: "b1", Name: "old-web-1", Project: "old", Service: "web", Status: "exited", Finished: old},
		{ID: "c1", Name: "scratch", Status: "exited", Finished: old},
	}}
	e := testEnv(t, snap)
	inv := &Inventory{keys: map[string]appRef{}}
	apps := e.containerApps(inv, snap, map[string][]string{"port:8081": {"shop.example.com/"}})
	byName := map[string]*App{}
	for _, a := range apps {
		byName[a.Name] = a
	}
	shop := byName["shop"]
	if shop == nil || shop.Status != Fail || shop.State != "1 of 3 containers down" {
		t.Fatalf("shop = %+v", shop)
	}
	if shop.Services[0].Name != "api" || shop.Services[0].Ports[0].Routes[0] != "shop.example.com/" || !shop.Services[0].Ports[0].Local {
		t.Errorf("api service = %+v", shop.Services[0])
	}
	if shop.Services[1].Status != Info {
		t.Errorf("a one-off job that exited 0 is not a failure: %+v", shop.Services[1])
	}
	if o := byName["old"]; o == nil || !o.Stopped || !strings.HasPrefix(o.State, "stopped 3 months ago") {
		t.Errorf("a fully stopped project is stopped, not broken: %+v", o)
	}
	if len(inv.Stopped) != 1 || inv.Stopped[0].Name != "scratch" || inv.Stopped[0].State != "exited" {
		t.Errorf("stopped = %v", inv.Stopped)
	}
	if a, svc := inv.AppOf(&Probe{Host: "127.0.0.1", Port: 8081}); a != shop || svc.Name != "api" {
		t.Errorf("AppOf(:8081) = %v %v", a, svc)
	}
}

func TestHint(t *testing.T) {
	inv := &Inventory{Apps: []*App{
		{Name: "old-api", Kind: "process", Ports: []AppPort{{Port: 9001}}},
		{Name: "redis", Kind: "process", Ports: []AppPort{{Port: 6379}}},
		{Name: "shop", Kind: "process", Ports: []AppPort{{Port: 9000, Routes: []string{"shop/"}}}},
	}}
	f := &Finding{Code: "nothing-listening"}
	inv.Hint([]*Finding{f})
	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0].Text, "old-api :9001") || strings.Contains(f.Evidence[0].Text, "redis") {
		t.Errorf("evidence = %+v", f.Evidence)
	}
}

func TestDepStepsLocalhostInContainer(t *testing.T) {
	p := &Probe{Container: &docker.Container{Name: "shop-api-1", Service: "api", Status: "restarting"}, Deps: []*Dep{
		{Name: "localhost", EnvKey: "DATABASE_URL", Probe: &Probe{Host: "localhost", Port: 5432, TCP: network.Result{Class: network.Unknown}}},
	}}
	steps := depSteps(p)
	if len(steps) != 1 || steps[0].Status != Fail || !strings.Contains(steps[0].Detail, "api container itself") {
		t.Errorf("steps = %+v", steps)
	}
}

func TestPortCandidates(t *testing.T) {
	now := time.Now()
	f := portCandidates(3000, []*docker.Container{
		{Name: "grafana", Status: "exited", Finished: now.Add(-180 * 24 * time.Hour)},
		{Name: "shop-web-1", Project: "shop", Service: "web", WorkingDir: "/srv/shop", Status: "exited", Finished: now.Add(-2 * time.Hour)},
	})
	if !strings.Contains(f.Title, "2 stopped containers") || !strings.HasPrefix(f.Evidence[0].Text, "shop · web") {
		t.Errorf("finding = %+v", f)
	}
	if f.Fixes[0].Command != "cd /srv/shop && docker compose up -d web" {
		t.Errorf("fix = %+v", f.Fixes[0])
	}
}
