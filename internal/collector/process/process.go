// Package process finds which processes listen on TCP ports and how they were started.
package process

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/runner"
)

type Owner struct {
	PID         int
	Name        string
	Cmdline     string
	Exe         string
	Cwd         string
	User        string
	Started     time.Time
	Unit        string // systemd unit, Linux only
	ContainerID string // set when the cgroup shows a container, Linux only
}

func (o Owner) Label() string {
	if o.Unit != "" {
		return "systemd: " + o.Unit
	}
	if o.Name == "" {
		return "pid " + strconv.Itoa(o.PID)
	}
	return o.Name + " (pid " + strconv.Itoa(o.PID) + ")"
}

func (o Owner) IsDockerProxy() bool {
	switch o.Name {
	case "docker-proxy", "com.docker.backend", "com.docker.vpnkit", "vpnkit", "OrbStack", "OrbStack Helper", "limactl", "ssh", "rootlessport":
		return true
	}
	return strings.Contains(o.Cmdline, "docker-proxy")
}

// Program is the most useful short name: the binary name, or the script for interpreters.
func (o Owner) Program() string {
	args := strings.Fields(o.Cmdline)
	if len(args) == 0 {
		return o.Name
	}
	base := filepath.Base(args[0])
	switch strings.TrimRight(strings.ToLower(base), "0123456789.") {
	case "python", "node", "ruby", "php", "java", "bun", "deno", "perl", "bash", "sh":
		for i, a := range args[1:] {
			if a == "-m" && i+2 < len(args) {
				return args[i+2]
			}
			if !strings.HasPrefix(a, "-") {
				return strings.TrimSuffix(filepath.Base(a), filepath.Ext(a))
			}
		}
	}
	if o.Name != "" {
		return o.Name
	}
	return base
}

// ShortCmdline drops the directory of a long interpreter or binary path.
func (o Owner) ShortCmdline() string {
	args := strings.Fields(o.Cmdline)
	if len(args) == 0 || len(args[0]) <= 40 {
		return o.Cmdline
	}
	args[0] = filepath.Base(args[0])
	return strings.Join(args, " ")
}

// Listener is one listening TCP socket.
type Listener struct {
	Addr  string // "" or "*" means all interfaces
	Port  int
	Owner *Owner // nil when the process belongs to another user and we aren't root
}

func (l Listener) LocalOnly() bool {
	return strings.HasPrefix(l.Addr, "127.") || l.Addr == "::1" || l.Addr == "localhost"
}

type Finder struct {
	Runner    runner.Runner
	listeners []Listener
	loaded    bool
}

// Lookup returns the owner of a listening TCP port. listening reports whether
// anything listens at all; owner is nil when the process can't be seen
// (usually because it belongs to another user and we're not root).
func (f *Finder) Lookup(ctx context.Context, port int) (owner *Owner, listening bool, err error) {
	ls, err := f.Listeners(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, l := range ls {
		if l.Port == port {
			listening = true
			if l.Owner != nil {
				return l.Owner, true, nil
			}
		}
	}
	return nil, listening, nil
}

// Listeners returns every listening TCP socket on the machine, read once.
func (f *Finder) Listeners(ctx context.Context) ([]Listener, error) {
	if f.loaded {
		return f.listeners, nil
	}
	ls, err := f.list(ctx)
	if err != nil {
		return nil, err
	}
	f.listeners, f.loaded = ls, true
	return ls, nil
}
