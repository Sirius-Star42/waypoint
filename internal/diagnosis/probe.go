package diagnosis

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/collector/compose"
	"github.com/Sirius-Star42/waypoint/internal/collector/docker"
	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/collector/process"
	"github.com/Sirius-Star42/waypoint/internal/collector/systemd"
	"github.com/Sirius-Star42/waypoint/internal/nginx"
	"github.com/Sirius-Star42/waypoint/internal/runner"
)

type Env struct {
	Ctx       context.Context
	Runner    runner.Runner
	Timeout   time.Duration
	NginxPath string
	Dir       string

	mu         sync.Mutex
	notes      []string
	dockerOnce sync.Once
	docker     *docker.Snapshot
	nginxOnce  sync.Once
	nginx      *nginx.Config
	nginxErr   error
	finder     *process.Finder
	systemd    *systemd.Systemd
	sdOnce     sync.Once
	projects   map[string]*compose.Project
	local      *compose.Project
	localOnce  sync.Once
	probes     map[string]*Probe
}

func NewEnv(ctx context.Context, r runner.Runner, timeout time.Duration, dir string) *Env {
	return &Env{Ctx: ctx, Runner: r, Timeout: timeout, Dir: dir,
		finder: &process.Finder{Runner: r}, projects: map[string]*compose.Project{}, probes: map[string]*Probe{}}
}

func (e *Env) Note(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, n := range e.notes {
		if n == s {
			return
		}
	}
	e.notes = append(e.notes, s)
}

func (e *Env) Notes() []string { return e.notes }

func (e *Env) Docker() *docker.Snapshot {
	e.dockerOnce.Do(func() {
		s, err := docker.Load(e.Ctx, e.Runner)
		if err != nil {
			if err != docker.ErrUnavailable {
				e.Note(err.Error() + "; container checks skipped")
			}
			return
		}
		e.docker = s
	})
	return e.docker
}

func (e *Env) Nginx() (*nginx.Config, error) {
	e.nginxOnce.Do(func() {
		e.nginx, e.nginxErr = nginx.Load(e.Ctx, e.Runner, e.NginxPath)
		if e.nginx != nil {
			for _, n := range e.nginx.Notes {
				e.Note(n)
			}
		}
	})
	return e.nginx, e.nginxErr
}

func (e *Env) Systemd() *systemd.Systemd {
	e.sdOnce.Do(func() { e.systemd = systemd.New(e.Runner) })
	return e.systemd
}

func (e *Env) LocalCompose() *compose.Project {
	e.localOnce.Do(func() {
		if f := compose.Find(e.Dir); f != "" {
			e.local = e.compose(f)
		}
	})
	return e.local
}

func (e *Env) compose(file string) *compose.Project {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := e.projects[file]; ok {
		return p
	}
	p, err := compose.Load(file)
	if err != nil {
		p = nil
	}
	e.projects[file] = p
	return p
}

type Probe struct {
	Host string
	Port int
	Unix string
	Via  *docker.Container // probed from inside this container (nginx running in Docker)

	DNS  network.Result
	TCP  network.Result
	HTTP *network.HTTPResult

	Owner         *process.Owner
	Container     *docker.Container
	ContainerPort int
	Units         []*systemd.Unit
	Compose       *compose.Project

	Logs      []string
	LogSource string

	Deps []*Dep
}

type Dep struct {
	Name   string
	EnvKey string
	EnvVal string
	Probe  *Probe
}

func (p *Probe) Addr() string {
	if p.Unix != "" {
		return "unix:" + p.Unix
	}
	return p.Host + ":" + strconv.Itoa(p.Port)
}

func (p *Probe) Up() bool {
	if !p.TCP.OK() && p.TCP.Class != network.Unknown {
		return false
	}
	if p.Container != nil && (!p.Container.Running() || p.Container.Health == "unhealthy") {
		return false
	}
	return true
}

func (p *Probe) OwnerLabel() string {
	switch {
	case p.Container != nil:
		return p.Container.Label()
	case p.Owner != nil:
		return p.Owner.Label()
	}
	for _, u := range p.Units {
		return "systemd: " + u.Name
	}
	return ""
}

func (e *Env) ProbeEndpoint(ep nginx.Endpoint, via *docker.Container) *Probe {
	key := ep.String()
	if via != nil {
		key = via.Name + "|" + key
	}
	e.mu.Lock()
	if p, ok := e.probes[key]; ok {
		e.mu.Unlock()
		return p
	}
	e.mu.Unlock()
	p := e.probe(ep, via, 0)
	e.mu.Lock()
	e.probes[key] = p
	e.mu.Unlock()
	return p
}

func (e *Env) probe(ep nginx.Endpoint, via *docker.Container, depth int) *Probe {
	p := &Probe{Host: ep.Host, Port: ep.Port, Unix: ep.Unix, Via: via}
	switch {
	case ep.Unix != "":
		p.TCP = network.DialUnix(e.Ctx, ep.Unix, e.Timeout)
		if !p.TCP.OK() {
			p.Units = e.unitsMatching(strings.TrimSuffix(lastPath(ep.Unix), ".sock"))
		}
	case via != nil:
		e.probeInContainer(p, via)
	default:
		e.probeHost(p)
	}
	if p.Container != nil {
		e.attachCompose(p, depth)
	}
	e.collectLogs(p)
	return p
}

func (e *Env) probeHost(p *Probe) {
	if !network.IsLocal(p.Host) {
		if _, p.DNS = network.Resolve(e.Ctx, p.Host, e.Timeout); !p.DNS.OK() {
			return
		}
	}
	p.TCP = network.DialTCP(e.Ctx, p.Host, p.Port, e.Timeout)
	if !network.IsLocal(p.Host) {
		return
	}
	owner, _, err := e.finder.Lookup(e.Ctx, p.Port)
	if err != nil {
		e.Note(err.Error())
	}
	p.Owner = owner
	if p.TCP.OK() && owner == nil {
		e.Note("some listening processes belong to other users; run with sudo to see them")
	}
	if snap := e.Docker(); snap != nil {
		if owner != nil && owner.ContainerID != "" {
			p.Container = snap.ByID(owner.ContainerID)
		}
		if p.Container == nil && (owner == nil || owner.IsDockerProxy() || !p.TCP.OK()) {
			if c, b := snap.ByHostPort(p.Port); c != nil {
				p.Container, p.ContainerPort = c, b.ContainerPort
			}
		}
	}
	if p.Container == nil && owner == nil && !p.TCP.OK() {
		p.Units = e.Systemd().ForPort(e.Ctx, p.Port)
	}
	if p.Container == nil && owner != nil && owner.Unit != "" {
		if u := e.Systemd().Status(e.Ctx, owner.Unit); u != nil {
			p.Units = []*systemd.Unit{u}
		}
	}
}

func (e *Env) probeInContainer(p *Probe, via *docker.Container) {
	snap := e.Docker()
	if network.IsLocal(p.Host) {
		p.Container = via
	} else {
		p.Container = snap.ByName(p.Host, via.NetworkNames())
	}
	p.ContainerPort = p.Port
	p.TCP = e.dialFrom(via, p.Host, p.Port)
}

// dialFrom opens a TCP connection from inside a container, using bash's /dev/tcp
// or busybox nc, whichever the image has.
func (e *Env) dialFrom(c *docker.Container, host string, port int) network.Result {
	secs := strconv.Itoa(max(1, int(e.Timeout.Seconds()+0.5)))
	script := `T=""; command -v timeout >/dev/null 2>&1 && T="timeout $2"
if command -v bash >/dev/null 2>&1; then exec $T bash -c "exec 3<>/dev/tcp/$0/$1"; else exec nc -z -w "$2" "$0" "$1"; fi`
	// docker exec itself adds startup time; the in-container timeout above is the real limit.
	ctx, cancel := context.WithTimeout(e.Ctx, e.Timeout+2*time.Second)
	defer cancel()
	start := time.Now()
	out, err := e.Runner.Combined(ctx, "docker", "exec", c.Name, "sh", "-c", script, host, strconv.Itoa(port), secs)
	r := network.Result{Class: network.OK, Took: time.Since(start)}
	if err == nil {
		return r
	}
	if ctx.Err() == context.DeadlineExceeded || strings.Contains(err.Error(), "exit status 124") {
		r.Class, r.Err = network.Timeout, fmt.Sprintf("timed out after %s", e.Timeout)
		return r
	}
	msg := strings.ToLower(out)
	r.Err = strings.TrimSpace(out)
	switch {
	case strings.Contains(msg, "executable file not found"), strings.Contains(msg, "oci runtime"), strings.Contains(msg, "is not running"), strings.Contains(msg, "is restarting"):
		r.Class, r.Err = network.Unknown, "could not run a check inside "+c.Name
	case strings.Contains(msg, "refused"):
		r.Class = network.Refused
	case strings.Contains(msg, "not known"), strings.Contains(msg, "bad address"), strings.Contains(msg, "resolve"), strings.Contains(msg, "unknown host"):
		r.Class = network.NoSuchHost
	case strings.Contains(msg, "timed out"), strings.Contains(msg, "timeout"):
		r.Class = network.Timeout
	case strings.Contains(msg, "no route"), strings.Contains(msg, "unreachable"):
		r.Class = network.Unreachable
	default:
		r.Class = network.Other
		if r.Err == "" {
			r.Err = err.Error()
		}
	}
	return r
}

func (e *Env) unitsMatching(word string) []*systemd.Unit {
	sd := e.Systemd()
	if sd == nil || word == "" {
		return nil
	}
	if u := sd.Status(e.Ctx, word+".service"); u != nil && u.Down() {
		return []*systemd.Unit{u}
	}
	return nil
}

func (e *Env) attachCompose(p *Probe, depth int) {
	c := p.Container
	if len(c.ComposeFiles) > 0 {
		p.Compose = e.compose(c.ComposeFiles[0])
	}
	if depth >= 2 {
		return
	}
	seen := map[string]bool{c.Service: true}
	add := func(d *Dep) {
		if seen[d.Name] {
			return
		}
		seen[d.Name] = true
		p.Deps = append(p.Deps, d)
	}
	for _, d := range envDeps(c, e.Docker()) {
		add(d)
	}
	if p.Compose != nil && c.Service != "" {
		if svc := p.Compose.Services[c.Service]; svc != nil {
			for _, name := range svc.DependsOn {
				add(&Dep{Name: name})
			}
		}
	}
	for _, d := range p.Deps {
		d.Probe = e.probeDep(c, d, depth+1)
	}
}

func (e *Env) probeDep(from *docker.Container, d *Dep, depth int) *Probe {
	if network.IsLocal(d.Name) {
		_, port := urlHostPort(d.EnvVal)
		p := &Probe{Host: d.Name, Port: port, Via: from}
		if from.Running() {
			p.TCP = e.dialFrom(from, "127.0.0.1", port)
		} else {
			p.TCP = network.Result{Class: network.Unknown, Err: "not checked, " + from.DisplayName() + " is not running"}
		}
		return p
	}
	snap := e.Docker()
	target := snap.ByService(from.Project, d.Name)
	if target == nil {
		target = snap.ByName(d.Name, from.NetworkNames())
	}
	port := 0
	if d.EnvVal != "" {
		_, port = urlHostPort(d.EnvVal)
	}
	if port == 0 && target != nil && len(target.Exposed) > 0 {
		port = target.Exposed[0]
	}
	p := &Probe{Host: d.Name, Port: port, Container: target, ContainerPort: port}
	switch {
	case target == nil:
		p.TCP = network.Result{Class: network.NoSuchHost, Err: "no container named " + d.Name}
	case !target.Running():
		p.TCP = network.Result{Class: network.Refused}
	case from.Running() && port != 0:
		p.TCP = e.dialFrom(from, d.Name, port)
	default:
		p.TCP = network.Result{Class: network.OK}
	}
	if target != nil {
		e.attachCompose(p, depth)
	}
	e.collectLogs(p)
	return p
}

func envDeps(c *docker.Container, snap *docker.Snapshot) []*Dep {
	var keys []string
	for k := range c.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*Dep
	for _, k := range keys {
		v := c.Env[k]
		host, port := urlHostPort(v)
		if host == "" || port == 0 && !strings.Contains(v, "://") {
			continue
		}
		if network.IsLocal(host) {
			out = append(out, &Dep{Name: host, EnvKey: k, EnvVal: v})
			continue
		}
		if snap.ByService(c.Project, host) != nil || snap.ByName(host, c.NetworkNames()) != nil {
			out = append(out, &Dep{Name: host, EnvKey: k, EnvVal: v})
		}
	}
	return out
}

func urlHostPort(v string) (string, int) {
	if !strings.Contains(v, "://") {
		host, port, ok := strings.Cut(v, ":")
		if !ok || strings.ContainsAny(host, "/ =") {
			return "", 0
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			return "", 0
		}
		return host, n
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return "", 0
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = defaultPorts[u.Scheme]
	}
	return u.Hostname(), port
}

var defaultPorts = map[string]int{
	"http": 80, "https": 443, "postgres": 5432, "postgresql": 5432, "mysql": 3306,
	"mariadb": 3306, "redis": 6379, "rediss": 6379, "mongodb": 27017, "amqp": 5672, "nats": 4222,
}

func (e *Env) collectLogs(p *Probe) {
	if c := p.Container; c != nil {
		if c.Running() && c.Health != "unhealthy" && c.RestartCount == 0 && p.TCP.OK() {
			return
		}
		out, err := e.Runner.Combined(e.Ctx, "docker", "logs", "--tail", "12", c.Name)
		if err == nil {
			p.Logs, p.LogSource = lastLines(out, 12), "docker logs "+c.Name
		}
		return
	}
	for _, u := range p.Units {
		if !u.Down() {
			continue
		}
		lines, err := e.Systemd().Logs(e.Ctx, u.Name, 12)
		if err != nil {
			e.Note("can't read the journal for " + u.Name + "; run with sudo to see its logs")
		}
		p.Logs, p.LogSource = lines, "journalctl -u "+u.Name
		return
	}
}

func lastLines(s string, n int) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimRight(l, "\r"))
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func lastPath(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
