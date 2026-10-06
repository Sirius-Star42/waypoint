package diagnosis

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/collector/docker"
	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/collector/process"
	"github.com/Sirius-Star42/waypoint/internal/nginx"
)

type Inventory struct {
	Apps      []*App
	System    []string
	Stopped   []StoppedContainer
	Unknown   []int
	Elsewhere []Remote
	Issues    []*Finding
	keys      map[string]appRef
}

// StoppedContainer is a container outside any compose project that is no longer running.
type StoppedContainer struct {
	Name  string
	State string
	At    time.Time
}

type Remote struct {
	Addr   string
	Routes []string
}

type App struct {
	Name      string
	Kind      string
	Status    Status
	State     string
	Facts     []Fact
	Ports     []AppPort
	Services  []*AppService
	Notes     []string
	Stopped   bool
	StoppedAt time.Time
	single    *AppService
}

type Fact struct{ Label, Value string }

type AppPort struct {
	Port   int
	Local  bool
	Down   bool // the app should serve this port but isn't running
	Routes []string
}

type AppService struct {
	Name      string
	Status    Status
	State     string
	Ports     []AppPort
	Container *docker.Container
}

type appRef struct {
	app *App
	svc *AppService
}

// Running reports whether any app on the machine is running.
func (inv *Inventory) Running() bool {
	for _, a := range inv.Apps {
		if !a.Stopped {
			return true
		}
	}
	return false
}

// AppOf finds the app (and compose service) behind a probe.
func (inv *Inventory) AppOf(p *Probe) (*App, *AppService) {
	if inv == nil || p == nil {
		return nil, nil
	}
	if p.Container != nil {
		if r, ok := inv.keys["container:"+p.Container.ID]; ok {
			return r.app, r.svc
		}
	}
	if p.Unix != "" {
		r := inv.keys["unix:"+p.Unix]
		return r.app, r.svc
	}
	if network.IsLocal(p.Host) && p.Via == nil {
		r := inv.keys["port:"+strconv.Itoa(p.Port)]
		return r.app, r.svc
	}
	return nil, nil
}

// Routed reports whether any nginx route reaches this app.
func (a *App) Routed() bool {
	for _, p := range a.Ports {
		if len(p.Routes) > 0 {
			return true
		}
	}
	for _, s := range a.Services {
		for _, p := range s.Ports {
			if len(p.Routes) > 0 {
				return true
			}
		}
	}
	return false
}

// Inventory lists what runs on this machine, how it is started, and which
// nginx routes lead to it.
func (e *Env) Inventory() *Inventory {
	inv := &Inventory{keys: map[string]appRef{}}
	cfg, _ := e.Nginx()
	routes, remotes := e.routeIndex(cfg)
	snap := e.Docker()
	listeners, err := e.finder.Listeners(e.Ctx)
	if err != nil {
		e.Note(err.Error())
	}

	containerApps := e.containerApps(inv, snap, routes)
	units := map[string]*App{}
	procs := map[int]*App{}
	var system []string
	unknown := map[int]bool{}
	for _, l := range listeners {
		o := l.Owner
		switch {
		case o == nil:
			unknown[l.Port] = true
			continue
		case o.IsDockerProxy():
			continue
		case o.ContainerID != "" && snap.ByID(o.ContainerID) != nil:
			c := snap.ByID(o.ContainerID)
			if r, ok := inv.keys["container:"+c.ID]; ok && r.svc != nil {
				addPort(&r.svc.Ports, l, routes, "container:"+c.ID)
			}
			continue
		case o.Name == "nginx" || strings.HasPrefix(o.Name, "nginx:"):
			continue
		case isSystem(o):
			system = append(system, fmt.Sprintf("%s :%d", o.Program(), l.Port))
			continue
		}
		var a *App
		if o.Unit != "" {
			if a = units[o.Unit]; a == nil {
				a = e.unitApp(o)
				units[o.Unit] = a
				inv.Apps = append(inv.Apps, a)
			}
		} else if a = procs[o.PID]; a == nil {
			a = processApp(o)
			procs[o.PID] = a
			inv.Apps = append(inv.Apps, a)
		}
		addPort(&a.Ports, l, routes, "port:"+strconv.Itoa(l.Port))
		inv.keys["port:"+strconv.Itoa(l.Port)] = appRef{app: a}
		exposureNote(a, l)
	}
	inv.Apps = append(inv.Apps, containerApps...)
	inv.Apps = append(inv.Apps, e.failedUnits(units, inv, routes)...)

	for port := range unknown {
		if _, ok := inv.keys["port:"+strconv.Itoa(port)]; !ok {
			if c, _ := snap.ByHostPort(port); c == nil {
				inv.Unknown = append(inv.Unknown, port)
			}
		}
	}
	sort.Ints(inv.Unknown)
	if len(inv.Unknown) > 0 {
		e.Note("some ports belong to other users' processes; run with sudo to see what they are")
	}
	sort.Strings(system)
	inv.System = dedupe(system)
	for _, r := range remotes {
		inv.Elsewhere = append(inv.Elsewhere, *r)
	}
	sort.Slice(inv.Elsewhere, func(i, j int) bool { return inv.Elsewhere[i].Addr < inv.Elsewhere[j].Addr })

	for _, a := range inv.Apps {
		if cfg != nil && len(a.Ports) > 0 && !a.Routed() && a.Kind != "docker compose" {
			a.Notes = append(a.Notes, "no nginx route points here")
		}
	}
	sort.SliceStable(inv.Apps, func(i, j int) bool {
		a, b := inv.Apps[i], inv.Apps[j]
		if a.Stopped != b.Stopped {
			return b.Stopped
		}
		if a.Stopped && !a.StoppedAt.Equal(b.StoppedAt) {
			return a.StoppedAt.After(b.StoppedAt)
		}
		if (a.Status == Fail) != (b.Status == Fail) {
			return a.Status == Fail
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	e.inventoryIssues(inv, snap)
	return inv
}

func (e *Env) containerApps(inv *Inventory, snap *docker.Snapshot, routes map[string][]string) []*App {
	if snap == nil {
		return nil
	}
	projects := map[string]*App{}
	var out []*App
	for _, c := range snap.Containers {
		if c.Project == "" && !c.Running() {
			inv.Stopped = append(inv.Stopped, StoppedContainer{Name: c.Name, State: stoppedState(c), At: c.Finished})
			continue
		}
		svc := &AppService{Name: c.DisplayName(), Container: c}
		svc.Status, svc.State = containerState(c)
		for _, b := range c.Bindings {
			l := process.Listener{Port: b.HostPort, Addr: b.HostIP}
			addPort(&svc.Ports, l, routes, "port:"+strconv.Itoa(b.HostPort))
		}
		for i := range svc.Ports {
			svc.Ports[i].Routes = dedupe(append(svc.Ports[i].Routes, routes["container:"+c.ID]...))
		}
		if len(svc.Ports) == 0 && len(routes["container:"+c.ID]) > 0 {
			svc.Ports = []AppPort{{Routes: routes["container:"+c.ID]}}
		}
		if c.Project == "" {
			a := &App{Name: c.Name, Kind: "docker container", Status: svc.Status, State: svc.State, single: svc}
			a.Facts = append(a.Facts, Fact{"image", c.Image})
			a.Ports = svc.Ports
			a.Facts = append(a.Facts, Fact{"manage", "docker logs -f " + c.Name + "  ·  docker restart " + c.Name})
			inv.keys["container:"+c.ID] = appRef{app: a, svc: svc}
			for _, b := range c.Bindings {
				inv.keys["port:"+strconv.Itoa(b.HostPort)] = appRef{app: a, svc: svc}
			}
			out = append(out, a)
			continue
		}
		a := projects[c.Project]
		if a == nil {
			a = &App{Name: c.Project, Kind: "docker compose"}
			if len(c.ComposeFiles) > 0 {
				a.Facts = append(a.Facts, Fact{"file", c.ComposeFiles[0]})
			}
			if c.WorkingDir != "" {
				a.Facts = append(a.Facts, Fact{"manage", "cd " + c.WorkingDir + " && docker compose ps"})
			}
			projects[c.Project] = a
			out = append(out, a)
		}
		a.Services = append(a.Services, svc)
		inv.keys["container:"+c.ID] = appRef{app: a, svc: svc}
		for _, b := range c.Bindings {
			inv.keys["port:"+strconv.Itoa(b.HostPort)] = appRef{app: a, svc: svc}
		}
	}
	for _, a := range projects {
		sort.Slice(a.Services, func(i, j int) bool { return a.Services[i].Name < a.Services[j].Name })
		running, failed := 0, 0
		var last time.Time
		for _, s := range a.Services {
			if s.Container.Running() || s.Container.Status == "restarting" {
				running++
			}
			if s.Container.Finished.After(last) {
				last = s.Container.Finished
			}
		}
		if running == 0 {
			a.Status, a.Stopped = Info, true
			a.State = "stopped"
			if last.Year() > 1 {
				a.State += " " + Ago(last)
				a.StoppedAt = last
			}
			for _, s := range a.Services {
				s.Status = Info
			}
			continue
		}
		for _, s := range a.Services {
			if s.Status == Fail {
				failed++
			}
		}
		a.Status = Pass
		a.State = plural(len(a.Services), "container")
		if failed > 0 {
			a.Status = Fail
			a.State = fmt.Sprintf("%d of %d containers down", failed, len(a.Services))
		}
	}
	sort.SliceStable(inv.Stopped, func(i, j int) bool { return inv.Stopped[i].At.After(inv.Stopped[j].At) })
	return out
}

func containerState(c *docker.Container) (Status, string) {
	switch {
	case c.Status == "running" && c.Health == "unhealthy":
		return Fail, "running but unhealthy"
	case c.Status == "running" && c.RestartCount >= 3:
		return Fail, fmt.Sprintf("crashing (restarted %d×)", c.RestartCount)
	case c.Status == "running":
		return Pass, "running for " + since(c.Started)
	case c.Status == "restarting":
		return Fail, fmt.Sprintf("crashing (restarted %d×)", c.RestartCount)
	case c.Status == "exited" && c.ExitCode == 0:
		return Info, joinWords("finished", Ago(c.Finished))
	case c.Status == "exited" && (c.ExitCode == 143 || c.ExitCode == 130):
		return Warn, joinWords("stopped", Ago(c.Finished))
	}
	return Fail, stoppedText(c)
}

func stoppedText(c *docker.Container) string {
	s := "stopped"
	if c.Status == "exited" {
		s = "exited"
		if c.ExitCode != 0 {
			s += " with code " + strconv.Itoa(c.ExitCode)
		}
	}
	if ago := Ago(c.Finished); ago != "" {
		s += ", " + ago
	}
	return s
}

func stoppedState(c *docker.Container) string {
	if c.Status != "exited" {
		return "stopped"
	}
	if c.ExitCode != 0 {
		return "exited (code " + strconv.Itoa(c.ExitCode) + ")"
	}
	return "exited"
}

func (e *Env) unitApp(o *process.Owner) *App {
	a := &App{Name: strings.TrimSuffix(o.Unit, ".service"), Kind: "systemd service", Status: Pass}
	u := e.Systemd().Status(e.Ctx, o.Unit)
	cmd, dir, started, file, usr := o.ShortCmdline(), o.Cwd, o.Started, "", o.User
	if u != nil {
		if u.Exec != "" {
			cmd = u.Exec
		}
		if u.Dir != "" {
			dir = u.Dir
		}
		if !u.Started.IsZero() {
			started = u.Started
		}
		file = u.File
		if u.User != "" {
			usr = u.User
		}
	}
	a.State = "running for " + since(started)
	a.Facts = appendFact(a.Facts, "command", cmd)
	a.Facts = appendFact(a.Facts, "folder", dir)
	a.Facts = appendFact(a.Facts, "unit file", file)
	a.Facts = appendFact(a.Facts, "user", usr)
	a.Facts = append(a.Facts, Fact{"manage", "sudo systemctl restart " + a.Name + "  ·  journalctl -u " + a.Name + " -f"})
	return a
}

func processApp(o *process.Owner) *App {
	a := &App{Name: appName(o), Kind: "process", Status: Pass, State: "running for " + since(o.Started)}
	a.Facts = appendFact(a.Facts, "command", o.ShortCmdline())
	a.Facts = appendFact(a.Facts, "program", o.Exe)
	a.Facts = appendFact(a.Facts, "folder", o.Cwd)
	a.Facts = appendFact(a.Facts, "user", o.User)
	a.Facts = append(a.Facts, Fact{"pid", strconv.Itoa(o.PID)})
	if runtime.GOOS == "linux" {
		a.Notes = append(a.Notes, "started by hand, not by systemd or Docker: it won't come back after a reboot or crash")
	}
	return a
}

var genericNames = map[string]bool{"server": true, "main": true, "app": true, "index": true, "run": true,
	"start": true, "serve": true, "api": true, "web": true, "manage": true, "gunicorn": true, "uvicorn": true}

// appName picks a recognizable name: the program, or its folder when the program name is generic.
func appName(o *process.Owner) string {
	name := o.Program()
	if !genericNames[name] {
		return name
	}
	for _, dir := range []string{o.Cwd, filepath.Dir(o.Exe)} {
		base := filepath.Base(dir)
		if base == "bin" {
			base = filepath.Base(filepath.Dir(dir))
		}
		home := dir == "/home/"+base || dir == "/Users/"+base
		if dir != "" && base != "/" && base != "." && base != "root" && !home {
			return base
		}
	}
	return name
}

func since(t time.Time) string {
	if t.IsZero() || t.Year() < 2000 {
		return "?"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "a few seconds"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 48*time.Hour:
		return plural(int(d.Hours()), "hour")
	case d < 60*24*time.Hour:
		return plural(int(d.Hours()/24), "day")
	case d < 2*365*24*time.Hour:
		return plural(int(d.Hours()/24/30), "month")
	}
	return plural(int(d.Hours()/24/365), "year")
}

func joinWords(a, b string) string {
	return strings.TrimSpace(a + " " + b)
}

// Ago is "3 hours ago", or "" when t is unknown.
func Ago(t time.Time) string {
	if t.IsZero() || t.Year() < 2000 {
		return ""
	}
	return since(t) + " ago"
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return strconv.Itoa(n) + " " + w + "s"
}

func appendFact(fs []Fact, label, value string) []Fact {
	if v := strings.TrimSpace(value); v == "" || label == "folder" && v == "/" {
		return fs
	}
	return append(fs, Fact{label, value})
}

func addPort(ports *[]AppPort, l process.Listener, routes map[string][]string, key string) {
	local := l.LocalOnly()
	for i, p := range *ports {
		if p.Port == l.Port {
			(*ports)[i].Local = p.Local && local
			return
		}
	}
	*ports = append(*ports, AppPort{Port: l.Port, Local: local, Routes: routes[key]})
	sort.Slice(*ports, func(i, j int) bool { return (*ports)[i].Port < (*ports)[j].Port })
}

var dbPorts = map[int]string{5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 5672: "RabbitMQ"}

func exposureNote(a *App, l process.Listener) {
	if runtime.GOOS != "linux" || l.LocalOnly() {
		return
	}
	if db, ok := dbPorts[l.Port]; ok {
		a.Notes = append(a.Notes, fmt.Sprintf("%s on :%d listens on all interfaces; make sure a firewall blocks it from the internet", db, l.Port))
	}
}

var systemNames = map[string]bool{
	"sshd": true, "systemd-resolve": true, "systemd-resolved": true, "chronyd": true, "rpcbind": true, "cupsd": true,
	"avahi-daemon": true, "dnsmasq": true, "master": true, "exim4": true, "containerd": true, "dockerd": true,
	"rapportd": true, "ControlCe": true, "ControlCenter": true, "launchd": true, "mDNSResponder": true, "sharingd": true,
	"AirPlayXPCHelper": true, "systemd": true, "init": true, "smbd": true, "nmbd": true, "postfix": true, "unbound": true,
	"tailscaled": true, "cloudflared": true, "snapd": true, "sendmail": true, "xinetd": true,
}

func isSystem(o *process.Owner) bool {
	if systemNames[o.Name] || strings.HasPrefix(o.Name, "systemd-") || strings.HasPrefix(o.Name, "com.apple.") {
		return true
	}
	switch o.Unit {
	case "ssh.service", "sshd.service", "systemd-resolved.service", "cups.service", "postfix.service", "containerd.service", "docker.service":
		return true
	}
	for _, p := range []string{"/System/", "/usr/libexec/", "/usr/sbin/", "/Applications/", "/sbin/"} {
		if strings.HasPrefix(o.Exe, p) || strings.HasPrefix(o.Cmdline, p) {
			return true
		}
	}
	return false
}

// failedUnits lists local systemd services that have crashed, whether or not they hold a port.
func (e *Env) failedUnits(known map[string]*App, inv *Inventory, routes map[string][]string) []*App {
	sd := e.Systemd()
	if sd == nil {
		return nil
	}
	// Routed ports nobody listens on: which unit should be serving them?
	expected := map[string][]int{}
	for key := range routes {
		port, ok := strings.CutPrefix(key, "port:")
		if _, owned := inv.keys[key]; !ok || owned {
			continue
		}
		n, _ := strconv.Atoi(port)
		for _, u := range sd.ForPort(e.Ctx, n) {
			expected[u.Name] = append(expected[u.Name], n)
		}
	}
	var out []*App
	for _, name := range sd.Failed(e.Ctx) {
		if known[name] != nil {
			continue
		}
		u := sd.Status(e.Ctx, name)
		if u == nil || !strings.HasPrefix(u.File, "/etc/systemd/system/") {
			continue
		}
		a := &App{Name: strings.TrimSuffix(name, ".service"), Kind: "systemd service", Status: Fail, State: u.StateText()}
		a.Facts = appendFact(a.Facts, "command", u.Exec)
		a.Facts = appendFact(a.Facts, "folder", u.Dir)
		a.Facts = appendFact(a.Facts, "unit file", u.File)
		a.Facts = append(a.Facts, Fact{"manage", "journalctl -u " + a.Name + " -n 50  ·  sudo systemctl restart " + a.Name})
		sort.Ints(expected[name])
		for _, port := range expected[name] {
			a.Ports = append(a.Ports, AppPort{Port: port, Down: true, Routes: routes["port:"+strconv.Itoa(port)]})
			inv.keys["port:"+strconv.Itoa(port)] = appRef{app: a}
		}
		known[name] = a
		out = append(out, a)
	}
	return out
}

func (e *Env) inventoryIssues(inv *Inventory, snap *docker.Snapshot) {
	seen := map[string]bool{}
	add := func(f *Finding) {
		if f != nil && !seen[f.Title] {
			seen[f.Title] = true
			inv.Issues = append(inv.Issues, f)
		}
	}
	for _, a := range inv.Apps {
		if a.Status != Fail {
			continue
		}
		if a.Kind == "systemd service" {
			u := e.Systemd().Status(e.Ctx, a.Name+".service")
			if u == nil {
				continue
			}
			lines, _ := e.Systemd().Logs(e.Ctx, u.Name, 12)
			add(&Finding{
				Code:       "unit:" + u.Name,
				Title:      fmt.Sprintf("%s has crashed (%s)", u.Name, u.StateText()),
				Confidence: 0.85,
				Evidence:   []Evidence{fail("%s: %s since %s", u.Name, u.StateText(), u.Since)},
				Logs:       lines, LogSource: "journalctl -u " + u.Name,
				Fixes: []Fix{{"Full logs", "journalctl -u " + u.Name + " -n 100 --no-pager"}, {"Restart after fixing the cause", "sudo systemctl restart " + u.Name}},
			})
			continue
		}
		svcs := a.Services
		if a.single != nil {
			svcs = []*AppService{a.single}
		}
		for _, s := range svcs {
			c := s.Container
			if c == nil || s.Status != Fail {
				continue
			}
			p := &Probe{Host: c.DisplayName(), Container: c, TCP: network.Result{Class: network.Unknown}}
			if !c.Running() {
				p.TCP.Class = network.Refused
			}
			e.attachCompose(p, 0)
			e.collectLogs(p)
			root, _ := Root(e.Analyze(p))
			add(root)
		}
	}
}

// routeIndex maps "port:N", "unix:path" and "container:ID" to the nginx routes
// that lead there, plus upstreams on other machines.
func (e *Env) routeIndex(cfg *nginx.Config) (map[string][]string, map[string]*Remote) {
	idx := map[string][]string{}
	remotes := map[string]*Remote{}
	if cfg == nil {
		return idx, remotes
	}
	nc := e.nginxContainer(cfg)
	snap := e.Docker()
	var walk func(s *nginx.Server, locs []*nginx.Location)
	walk = func(s *nginx.Server, locs []*nginx.Location) {
		for _, l := range locs {
			walk(s, l.Children)
			if l.Upstream == nil || l.Upstream.Dynamic {
				continue
			}
			label := routeLabel(s, l)
			for _, ep := range l.Upstream.Endpoints {
				var key string
				switch {
				case ep.Unix != "":
					key = "unix:" + ep.Unix
				case nc != nil && !network.IsLocal(ep.Host) && ep.Host != "host.docker.internal":
					if c := snap.ByName(ep.Host, nc.NetworkNames()); c != nil {
						key = "container:" + c.ID
					}
				case network.IsLocal(ep.Host) || ep.Host == "host.docker.internal":
					key = "port:" + strconv.Itoa(ep.Port)
				default:
					r := remotes[ep.String()]
					if r == nil {
						r = &Remote{Addr: ep.String()}
						remotes[ep.String()] = r
					}
					r.Routes = dedupe(append(r.Routes, label))
				}
				if key != "" {
					idx[key] = dedupe(append(idx[key], label))
				}
			}
		}
	}
	for _, s := range cfg.Servers {
		if !s.Ignored() && s.Return == nil {
			walk(s, s.Locations)
		}
	}
	return idx, remotes
}

func routeLabel(s *nginx.Server, l *nginx.Location) string {
	name := s.DisplayName()
	if l.Mod == "" || l.Mod == "^~" {
		return name + l.Path
	}
	return name + " " + l.String()
}

func dedupe(list []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Hint points dead routes at running apps no route reaches: often the app
// moved to another port and the nginx config was never updated.
func (inv *Inventory) Hint(fs []*Finding) {
	var cands []string
	for _, a := range inv.Apps {
		if a.Stopped || a.Routed() || len(a.Ports) == 0 || a.Kind == "docker compose" {
			continue
		}
		if _, db := dbPorts[a.Ports[0].Port]; db {
			continue
		}
		cands = append(cands, fmt.Sprintf("%s :%d", a.Name, a.Ports[0].Port))
	}
	if len(cands) == 0 {
		return
	}
	for _, f := range fs {
		if f.Code == "nothing-listening" {
			f.Evidence = append(f.Evidence, warn("running here but not behind nginx: %s (did the port change?)", strings.Join(cands, ", ")))
		}
	}
}
