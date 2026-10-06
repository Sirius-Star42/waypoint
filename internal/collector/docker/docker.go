package docker

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/runner"
)

type Container struct {
	ID           string
	Name         string
	Image        string
	Status       string // running, exited, restarting, created, paused, dead
	ExitCode     int
	Health       string // healthy, unhealthy, starting, "" when no healthcheck
	HealthLog    string // output of the last healthcheck
	RestartCount int
	Started      time.Time
	Finished     time.Time
	Env          map[string]string
	Exposed      []int // container ports from EXPOSE / expose
	Bindings     []Binding
	Networks     map[string][]string // network → DNS names (service, aliases, container name)
	Project      string              // compose project
	Service      string              // compose service
	ComposeFiles []string
	WorkingDir   string
	DependsOn    []string // compose services this one depends on
}

type Binding struct {
	HostIP        string
	HostPort      int
	ContainerPort int
}

func (c *Container) Running() bool { return c.Status == "running" }

func (c *Container) DisplayName() string {
	if c.Service != "" {
		return c.Service
	}
	return c.Name
}

type Snapshot struct {
	Containers []*Container
}

var ErrUnavailable = errors.New("docker not available")

func Load(ctx context.Context, r runner.Runner) (*Snapshot, error) {
	if !r.Has("docker") {
		return nil, ErrUnavailable
	}
	ids, err := r.Run(ctx, "docker", "ps", "-aq")
	if err != nil {
		return nil, explain(err)
	}
	fields := strings.Fields(ids)
	if len(fields) == 0 {
		return &Snapshot{}, nil
	}
	out, err := r.Run(ctx, "docker", append([]string{"inspect"}, fields...)...)
	if err != nil && out == "" {
		return nil, explain(err)
	}
	return Parse(out)
}

func explain(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied"):
		return errors.New("permission denied talking to Docker (add your user to the docker group or run with sudo)")
	case strings.Contains(msg, "Cannot connect"), strings.Contains(msg, "daemon is running"), strings.Contains(msg, "daemon running"), strings.Contains(msg, "failed to connect"):
		return errors.New("Docker is not running")
	}
	return err
}

type inspect struct {
	ID     string `json:"Id"`
	Name   string
	Config struct {
		Image        string
		Env          []string
		ExposedPorts map[string]struct{}
		Labels       map[string]string
	}
	State struct {
		Status     string
		ExitCode   int
		StartedAt  time.Time
		FinishedAt time.Time
		Health     *struct {
			Status string
			Log    []struct{ Output string }
		}
	}
	RestartCount int
	HostConfig   struct {
		PortBindings map[string][]struct{ HostIp, HostPort string }
	}
	NetworkSettings struct {
		Ports    map[string][]struct{ HostIp, HostPort string }
		Networks map[string]struct {
			Aliases  []string
			DNSNames []string
		}
	}
}

func Parse(out string) (*Snapshot, error) {
	var raw []inspect
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, err
	}
	s := &Snapshot{}
	for _, in := range raw {
		c := &Container{
			ID:           in.ID,
			Name:         strings.TrimPrefix(in.Name, "/"),
			Image:        in.Config.Image,
			Status:       in.State.Status,
			ExitCode:     in.State.ExitCode,
			RestartCount: in.RestartCount,
			Started:      in.State.StartedAt,
			Finished:     in.State.FinishedAt,
			Env:          map[string]string{},
			Networks:     map[string][]string{},
			Project:      in.Config.Labels["com.docker.compose.project"],
			Service:      in.Config.Labels["com.docker.compose.service"],
			WorkingDir:   in.Config.Labels["com.docker.compose.project.working_dir"],
		}
		// "redis:service_started:false,postgres:service_healthy:true"
		for _, d := range strings.Split(in.Config.Labels["com.docker.compose.depends_on"], ",") {
			if name, _, _ := strings.Cut(d, ":"); name != "" {
				c.DependsOn = append(c.DependsOn, name)
			}
		}
		if f := in.Config.Labels["com.docker.compose.project.config_files"]; f != "" {
			c.ComposeFiles = strings.Split(f, ",")
		}
		if in.State.Health != nil {
			c.Health = in.State.Health.Status
			if n := len(in.State.Health.Log); n > 0 {
				c.HealthLog = strings.TrimSpace(in.State.Health.Log[n-1].Output)
			}
		}
		for _, e := range in.Config.Env {
			if k, v, ok := strings.Cut(e, "="); ok {
				c.Env[k] = v
			}
		}
		for p := range in.Config.ExposedPorts {
			if n, ok := tcpPort(p); ok {
				c.Exposed = append(c.Exposed, n)
			}
		}
		sort.Ints(c.Exposed)
		ports := in.NetworkSettings.Ports
		if !hasBindings(ports) {
			// Stopped containers lose NetworkSettings.Ports but keep the configured bindings.
			ports = in.HostConfig.PortBindings
		}
		for p, binds := range ports {
			cp, ok := tcpPort(p)
			if !ok {
				continue
			}
			for _, b := range binds {
				hp, err := strconv.Atoi(b.HostPort)
				if err != nil {
					continue
				}
				c.Bindings = append(c.Bindings, Binding{HostIP: b.HostIp, HostPort: hp, ContainerPort: cp})
			}
		}
		sort.Slice(c.Bindings, func(i, j int) bool { return c.Bindings[i].HostPort < c.Bindings[j].HostPort })
		for name, n := range in.NetworkSettings.Networks {
			names := append([]string{c.Name}, n.Aliases...)
			names = append(names, n.DNSNames...)
			if c.Service != "" {
				names = append(names, c.Service)
			}
			c.Networks[name] = names
		}
		s.Containers = append(s.Containers, c)
	}
	sort.Slice(s.Containers, func(i, j int) bool { return s.Containers[i].Name < s.Containers[j].Name })
	return s, nil
}

func hasBindings(ports map[string][]struct{ HostIp, HostPort string }) bool {
	for _, b := range ports {
		if len(b) > 0 {
			return true
		}
	}
	return false
}

func tcpPort(spec string) (int, bool) {
	p, proto, _ := strings.Cut(spec, "/")
	if proto != "" && proto != "tcp" {
		return 0, false
	}
	n, err := strconv.Atoi(p)
	return n, err == nil
}

// ByHostPort finds the container publishing port: a running one if any, else the one that stopped last.
func (s *Snapshot) ByHostPort(port int) (*Container, Binding) {
	var best *Container
	var bb Binding
	for _, c := range s.AllByHostPort(port) {
		if best == nil || c.Running() && !best.Running() || c.Running() == best.Running() && c.Finished.After(best.Finished) {
			best = c
			for _, b := range c.Bindings {
				if b.HostPort == port {
					bb = b
				}
			}
		}
	}
	return best, bb
}

func (s *Snapshot) AllByHostPort(port int) []*Container {
	if s == nil {
		return nil
	}
	var out []*Container
	for _, c := range s.Containers {
		for _, b := range c.Bindings {
			if b.HostPort == port {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func (s *Snapshot) ByID(id string) *Container {
	if s == nil || id == "" {
		return nil
	}
	for _, c := range s.Containers {
		if strings.HasPrefix(c.ID, id) || strings.HasPrefix(id, c.ID) {
			return c
		}
	}
	return nil
}

func (s *Snapshot) ByName(name string, networks []string) *Container {
	if s == nil {
		return nil
	}
	var fallback *Container
	for _, c := range s.Containers {
		for net, names := range c.Networks {
			for _, n := range names {
				if !strings.EqualFold(n, name) {
					continue
				}
				if networks == nil || contains(networks, net) {
					return c
				}
				if fallback == nil {
					fallback = c
				}
			}
		}
		if len(c.Networks) == 0 && (strings.EqualFold(c.Name, name) || strings.EqualFold(c.Service, name)) && fallback == nil {
			fallback = c
		}
	}
	return fallback
}

func (s *Snapshot) ByService(project, service string) *Container {
	if s == nil {
		return nil
	}
	for _, c := range s.Containers {
		if c.Service == service && (project == "" || c.Project == project) {
			return c
		}
	}
	return nil
}

func (c *Container) NetworkNames() []string {
	var out []string
	for n := range c.Networks {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func SharesNetwork(a, b *Container) bool {
	for n := range a.Networks {
		if _, ok := b.Networks[n]; ok {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (c *Container) Label() string {
	return "docker: " + c.DisplayName()
}

func (c *Container) StateText() string {
	switch {
	case c.Status == "running" && c.Health == "unhealthy":
		return "running, unhealthy"
	case c.Status == "running" && c.RestartCount > 0:
		return "running, restarted " + strconv.Itoa(c.RestartCount) + "×"
	case c.Status == "exited":
		return "exited with code " + strconv.Itoa(c.ExitCode)
	case c.Status == "restarting":
		return "restarting (" + plural(c.RestartCount, "restart") + ")"
	}
	return c.Status
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}
