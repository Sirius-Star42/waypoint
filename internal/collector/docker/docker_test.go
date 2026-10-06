package docker

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/runner"
)

func load(t *testing.T) *Snapshot {
	t.Helper()
	b, err := os.ReadFile("testdata/inspect.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParse(t *testing.T) {
	s := load(t)
	if len(s.Containers) != 3 {
		t.Fatalf("containers = %d", len(s.Containers))
	}
	api, b := s.ByHostPort(8080)
	if api == nil || api.Service != "api" || b.ContainerPort != 8080 {
		t.Fatalf("ByHostPort(8080) = %+v %+v", api, b)
	}
	if api.Env["DATABASE_URL"] == "" || api.RestartCount != 7 || api.Status != "restarting" {
		t.Errorf("api = %+v", api)
	}
	if len(api.ComposeFiles) != 1 || api.ComposeFiles[0] != "/home/me/shop/compose.yaml" {
		t.Errorf("compose files = %v", api.ComposeFiles)
	}
	pg := s.ByName("postgres", []string{"shop_default"})
	if pg == nil || pg.Health != "unhealthy" || pg.HealthLog != "pg_isready: no response" {
		t.Errorf("postgres = %+v", pg)
	}
	if s.ByName("postgres", []string{"other_net"}) != pg {
		t.Error("fallback to any network should still find postgres")
	}
	if w := s.ByName("old-worker", nil); w == nil || w.StateText() != "exited with code 137" {
		t.Errorf("stopped container lookup = %+v", w)
	}
	if !SharesNetwork(api, pg) {
		t.Error("api and postgres share shop_default")
	}
}

func TestLoadErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := Load(ctx, runner.Fake{}); err != ErrUnavailable {
		t.Errorf("no docker binary: err = %v", err)
	}
	f := runner.Fake{
		Tools: map[string]bool{"docker": true},
		Err:   map[string]error{"docker ps -aq": errString("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")},
	}
	if _, err := Load(ctx, f); err == nil || err.Error() != "Docker is not running" {
		t.Errorf("daemon down: err = %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestStoppedContainerKeepsBindings(t *testing.T) {
	c, b := load(t).ByHostPort(9000)
	if c == nil || c.Name != "old-worker" || b.ContainerPort != 9000 {
		t.Fatalf("got %+v %+v", c, b)
	}
}

func TestByHostPortPrefersRunningThenLatest(t *testing.T) {
	now := time.Now()
	bind := []Binding{{HostPort: 3000, ContainerPort: 3000}}
	s := &Snapshot{Containers: []*Container{
		{Name: "old", Status: "exited", Finished: now.Add(-90 * 24 * time.Hour), Bindings: bind},
		{Name: "recent", Status: "exited", Finished: now.Add(-time.Hour), Bindings: bind},
	}}
	if c, _ := s.ByHostPort(3000); c == nil || c.Name != "recent" {
		t.Errorf("stopped: got %v, want the one that stopped last", c)
	}
	s.Containers = append(s.Containers, &Container{Name: "live", Status: "running", Bindings: bind})
	if c, _ := s.ByHostPort(3000); c == nil || c.Name != "live" {
		t.Errorf("got %v, want the running one", c)
	}
}
