package diagnosis

import (
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/collector/compose"
	"github.com/Sirius-Star42/waypoint/internal/collector/docker"
	"github.com/Sirius-Star42/waypoint/internal/collector/network"
)

type Status int

const (
	Pass Status = iota
	Fail
	Warn
	Info
)

type Evidence struct {
	Status Status
	Text   string
}

type Fix struct {
	Text    string
	Command string
}

type Finding struct {
	Title      string
	Detail     string
	Confidence float64
	Depth      int
	// Symptom findings can be caused by a failing dependency; Root prefers that dependency.
	Symptom bool
	// Code marks findings other parts of waypoint add context to.
	Code      string
	Evidence  []Evidence
	Logs      []string
	LogSource string
	Fixes     []Fix
}

func pass(f string, a ...any) Evidence { return Evidence{Pass, fmt.Sprintf(f, a...)} }
func fail(f string, a ...any) Evidence { return Evidence{Fail, fmt.Sprintf(f, a...)} }
func warn(f string, a ...any) Evidence { return Evidence{Warn, fmt.Sprintf(f, a...)} }

func (e *Env) Analyze(p *Probe) []*Finding {
	return e.analyze(p, 0, map[*Probe]bool{})
}

func (e *Env) analyze(p *Probe, depth int, seen map[*Probe]bool) []*Finding {
	if p == nil || seen[p] {
		return nil
	}
	seen[p] = true
	var out []*Finding
	for _, d := range p.Deps {
		if f := localhostDep(p, d, e.Docker()); f != nil {
			f.Depth = depth + 1
			out = append(out, f)
			continue
		}
		out = append(out, e.analyze(d.Probe, depth+1, seen)...)
	}
	if f := e.rule(p); f != nil {
		f.Depth = depth
		if len(f.Logs) == 0 {
			f.Logs, f.LogSource = p.Logs, p.LogSource
		}
		out = append(out, f)
	}
	return out
}

func name(p *Probe) string {
	if p.Container != nil {
		return p.Container.DisplayName()
	}
	return p.Addr()
}

func (e *Env) rule(p *Probe) *Finding {
	c := p.Container
	switch {
	case p.DNS.Class == network.NoSuchHost:
		return &Finding{
			Title:      p.Host + " does not resolve",
			Detail:     "There is no DNS record for this name, or the resolver can't be reached.",
			Confidence: 0.95,
			Evidence:   []Evidence{fail("DNS lookup for %s: %s", p.Host, p.DNS.Err)},
			Fixes:      []Fix{{"Check the record", "dig +short " + p.Host}},
		}

	case p.Via != nil && network.IsLocal(p.Host) && !p.TCP.OK() && p.TCP.Class != network.Unknown:
		return &Finding{
			Title: fmt.Sprintf("%s points to %s, but inside the %s container that is the container itself", "nginx", p.Addr(), p.Via.DisplayName()),
			Detail: "nginx runs in Docker, so localhost/127.0.0.1 means the nginx container, not your machine " +
				"or the app container.",
			Confidence: 0.9,
			Evidence:   []Evidence{pass("nginx runs in container %s", p.Via.Name), fail("nothing listens on %s inside it", p.Addr())},
			Fixes: []Fix{
				{"Point proxy_pass at the app's compose service name, e.g.", "proxy_pass http://api:" + strconv.Itoa(p.Port) + ";"},
				{"or, for an app running on the host:", "proxy_pass http://host.docker.internal:" + strconv.Itoa(p.Port) + ";"},
			},
		}

	case c != nil && (c.Status == "exited" || c.Status == "dead" || c.Status == "created"):
		return &Finding{
			Title:      fmt.Sprintf("container %s is not running (%s)", c.DisplayName(), c.StateText()),
			Detail:     exitMeaning(c.ExitCode),
			Confidence: 0.9,
			Symptom:    c.ExitCode != 0 && c.ExitCode != 143 && c.ExitCode != 137,
			Evidence:   []Evidence{fail("%s: %s", c.Name, c.StateText())},
			Fixes:      []Fix{{"See why it stopped", "docker logs --tail 100 " + c.Name}, startContainer(c)},
		}

	case c != nil && (c.Status == "restarting" || c.RestartCount >= 3):
		return &Finding{
			Title:      fmt.Sprintf("container %s keeps crashing (restarted %d×)", c.DisplayName(), c.RestartCount),
			Detail:     "Docker restarts it, it fails again. The reason is almost always in the last log lines.",
			Confidence: 0.9,
			Symptom:    true,
			Evidence:   []Evidence{fail("%s: %s, last exit code %d", c.Name, c.StateText(), c.ExitCode)},
			Fixes:      []Fix{{"Full logs", "docker logs --tail 200 " + c.Name}},
		}

	case c != nil && c.Health == "unhealthy":
		f := &Finding{
			Title:      fmt.Sprintf("container %s is running but unhealthy", c.DisplayName()),
			Confidence: 0.8,
			Symptom:    true,
			Evidence:   []Evidence{pass("%s is running", c.Name), fail("healthcheck failing")},
			Fixes:      []Fix{{"Healthcheck details", "docker inspect --format '{{json .State.Health}}' " + c.Name}},
		}
		if c.HealthLog != "" {
			f.Evidence = append(f.Evidence, fail("last healthcheck: %s", oneLine(c.HealthLog)))
		}
		return f

	case p.Via != nil && p.TCP.Class == network.NoSuchHost:
		return e.unresolvableInDocker(p)

	case c != nil && c.Running() && !p.TCP.OK() && p.TCP.Class != network.Unknown:
		return wrongPortOrBind(p)

	case len(p.Units) > 0 && p.Units[0].Down():
		u := p.Units[0]
		return &Finding{
			Code:       "unit:" + u.Name,
			Title:      fmt.Sprintf("%s is %s", u.Name, u.StateText()),
			Detail:     "The systemd service that serves this port is not running.",
			Confidence: 0.85,
			Evidence: []Evidence{
				fail("nothing listening on %s", p.Addr()),
				fail("%s mentions port %d and is %s since %s", u.Name, p.Port, u.Active, u.Since),
			},
			Fixes: []Fix{
				{"Full logs", "journalctl -u " + u.Name + " -n 100 --no-pager"},
				{"Restart after fixing the cause", "sudo systemctl restart " + u.Name},
			},
		}

	case p.Unix != "" && !p.TCP.OK():
		return &Finding{
			Title:      "nothing is listening on " + p.Addr(),
			Detail:     "The socket file is missing or nobody accepts on it: the service behind it (php-fpm, gunicorn, ...) isn't running.",
			Confidence: 0.75,
			Evidence:   []Evidence{fail("%s: %s", p.Addr(), p.TCP.Err)},
			Fixes:      []Fix{{"Find the service that should create it", "grep -rl " + lastPath(p.Unix) + " /etc/systemd/system /etc/php 2>/dev/null"}},
		}

	case p.TCP.Class == network.Refused:
		if f := e.portExpectedByCompose(p); f != nil {
			return f
		}
		return &Finding{
			Code:       "nothing-listening",
			Title:      "nothing is listening on " + p.Addr(),
			Detail:     "The connection was refused: no process, container or service holds this port.",
			Confidence: 0.75,
			Evidence:   []Evidence{fail("connect %s: %s", p.Addr(), p.TCP.Err)},
			Fixes:      []Fix{{"Start the app that should serve port " + strconv.Itoa(p.Port) + ", then check", listenersCmd(p.Port)}},
		}

	case p.TCP.Class == network.Timeout:
		return &Finding{
			Title:      "connection to " + p.Addr() + " times out",
			Detail:     "Packets are dropped: a firewall or security group, a wrong IP, or a hung process.",
			Confidence: 0.6,
			Evidence:   []Evidence{fail("connect %s: timed out", p.Addr())},
			Fixes:      []Fix{{"Check the firewall", "sudo iptables -S | grep " + strconv.Itoa(p.Port) + "   # or: sudo ufw status"}},
		}

	case p.TCP.Class == network.Unreachable:
		return &Finding{
			Title:      p.Addr() + " is unreachable",
			Detail:     "There is no network route to this address.",
			Confidence: 0.7,
			Evidence:   []Evidence{fail("connect %s: %s", p.Addr(), p.TCP.Err)},
		}

	case p.TCP.OK() && p.HTTP != nil && !p.HTTP.OK():
		f := &Finding{
			Title:      name(p) + " accepts connections but doesn't answer HTTP",
			Detail:     "TCP works, the request fails after connecting. The app may be starting, crashing per request, or speaking another protocol (TLS?).",
			Confidence: 0.75,
			Symptom:    true,
			Evidence:   []Evidence{pass("TCP connect %s", p.Addr()), fail("HTTP request: %s", p.HTTP.Err)},
		}
		if c != nil {
			f.Detail = "Docker forwards the port, but the app inside isn't answering. Often it listens on 127.0.0.1 inside the container instead of 0.0.0.0."
			f.Fixes = []Fix{{"Check what listens inside", "docker exec " + c.Name + " sh -c 'ss -lnt || netstat -lnt'"}, {"Logs", "docker logs --tail 100 " + c.Name}}
		}
		return f

	case p.HTTP != nil && p.HTTP.Status >= 500:
		f := &Finding{
			Title:      fmt.Sprintf("%s answers HTTP %d", name(p), p.HTTP.Status),
			Detail:     "The app is reachable but fails the request itself; its logs will say why.",
			Confidence: 0.6,
			Symptom:    true,
			Evidence:   []Evidence{pass("TCP connect %s", p.Addr()), fail("HTTP %d", p.HTTP.Status)},
		}
		return f
	}
	if f := e.portExpectedByCompose(p); f != nil {
		return f
	}
	return nil
}

func (e *Env) unresolvableInDocker(p *Probe) *Finding {
	snap := e.Docker()
	if other := snap.ByName(p.Host, nil); other != nil && other.Running() && !docker.SharesNetwork(other, p.Via) {
		return &Finding{
			Title: fmt.Sprintf("%s is not on the same Docker network as %s", other.DisplayName(), p.Via.DisplayName()),
			Detail: "Container names only resolve between containers that share a network, so nginx can't find " +
				p.Host + ".",
			Confidence: 0.9,
			Evidence: []Evidence{
				pass("%s is running", other.Name),
				fail("%s networks: %s", p.Via.Name, strings.Join(p.Via.NetworkNames(), ", ")),
				fail("%s networks: %s", other.Name, strings.Join(other.NetworkNames(), ", ")),
			},
			Fixes: []Fix{{"Connect it to nginx's network", "docker network connect " + firstOr(p.Via.NetworkNames(), "<network>") + " " + other.Name}},
		}
	}
	return &Finding{
		Title:      fmt.Sprintf("%s can't resolve %s", p.Via.DisplayName(), p.Host),
		Detail:     "No running container or host with this name is reachable from the nginx container.",
		Confidence: 0.85,
		Evidence:   []Evidence{fail("lookup %s from %s: %s", p.Host, p.Via.Name, p.TCP.Err)},
		Fixes:      []Fix{{"List services and their state", "docker compose ps -a"}},
	}
}

func wrongPortOrBind(p *Probe) *Finding {
	c := p.Container
	port := p.ContainerPort
	if port == 0 {
		port = p.Port
	}
	if len(c.Exposed) > 0 && !containsInt(c.Exposed, port) {
		return &Finding{
			Title:      fmt.Sprintf("%s is reached on port %d, but the container listens on %s", c.DisplayName(), port, joinInts(c.Exposed)),
			Detail:     "The port in the config doesn't match the port the app exposes.",
			Confidence: 0.85,
			Evidence: []Evidence{
				pass("%s is running", c.Name),
				fail("connect %s: %s", p.Addr(), p.TCP.Err),
				warn("image exposes %s", joinInts(c.Exposed)),
			},
			Fixes: []Fix{{"Use the exposed port in proxy_pass / ports", fmt.Sprintf("%s:%d", p.Host, c.Exposed[0])}},
		}
	}
	return &Finding{
		Title:      fmt.Sprintf("%s is running but nothing listens on port %d inside it", c.DisplayName(), port),
		Detail:     "The app is still starting, crashed inside the container, or listens on 127.0.0.1 instead of 0.0.0.0.",
		Confidence: 0.8,
		Symptom:    true,
		Evidence:   []Evidence{pass("%s is running", c.Name), fail("connect %s: %s", p.Addr(), p.TCP.Err)},
		Fixes:      []Fix{{"Check what listens inside", "docker exec " + c.Name + " sh -c 'ss -lnt || netstat -lnt'"}},
	}
}

func (e *Env) portExpectedByCompose(p *Probe) *Finding {
	proj := e.LocalCompose()
	if proj == nil || p.Unix != "" || !network.IsLocal(p.Host) {
		return nil
	}
	svc := proj.ByHostPort(p.Port)
	if svc == nil {
		return nil
	}
	if p.Owner != nil && !p.Owner.IsDockerProxy() && (p.Container == nil || p.Container.Service != svc.Name) {
		return &Finding{
			Title:      fmt.Sprintf("port %d is taken by %s, not by compose service %s", p.Port, p.Owner.Label(), svc.Name),
			Detail:     "Your compose file publishes this port, but another process already holds it, so the container can't bind it.",
			Confidence: 0.85,
			Evidence: []Evidence{
				warn("%s publishes %d", svc.Name, p.Port),
				fail("port %d owner: %s: %s", p.Port, p.Owner.Label(), p.Owner.Cmdline),
			},
			Fixes: []Fix{{"See the process", fmt.Sprintf("ps -o pid,user,command -p %d", p.Owner.PID)}, {"Stop it, or change the port in " + shortPath(proj.File), ""}},
		}
	}
	if p.Container == nil && !p.TCP.OK() {
		return &Finding{
			Title:      fmt.Sprintf("compose service %s publishes port %d but isn't running", svc.Name, p.Port),
			Confidence: 0.85,
			Evidence:   []Evidence{warn("%s maps %d → %d", shortPath(proj.File), p.Port, portOf(svc.Ports, p.Port)), fail("no container for %s", svc.Name)},
			Fixes:      []Fix{{"Start it", "docker compose up -d " + svc.Name}},
		}
	}
	return nil
}

func localhostDep(p *Probe, d *Dep, snap *docker.Snapshot) *Finding {
	if !network.IsLocal(d.Name) || d.Probe == nil || d.Probe.TCP.OK() || p.Container == nil {
		return nil
	}
	_, port := urlHostPort(d.EnvVal)
	var target *docker.Container
	if snap != nil {
		for _, c := range snap.Containers {
			if c != p.Container && c.Project == p.Container.Project && containsInt(c.Exposed, port) {
				target = c
				break
			}
		}
	}
	self := p.Container.DisplayName()
	f := &Finding{
		Title:  fmt.Sprintf("%s connects to %s:%d, but inside a container localhost is the container itself", self, d.Name, port),
		Detail: fmt.Sprintf("%s=%s is resolved inside the %s container, where nothing listens on %d.", d.EnvKey, redact(d.EnvVal), self, port),
		Evidence: []Evidence{
			fail("%s=%s", d.EnvKey, redact(d.EnvVal)),
		},
		Confidence: 0.8,
	}
	if p.Container.RestartCount > 0 || !p.Container.Running() {
		f.Confidence = 0.92
		f.Evidence = append(f.Evidence, fail("%s: %s", p.Container.Name, p.Container.StateText()))
	}
	if target != nil {
		svc := target.DisplayName()
		f.Evidence = append(f.Evidence, pass("%s exposes %d and is reachable as %s:%d", target.Name, port, svc, port))
		f.Fixes = []Fix{
			{"Use the service name instead of " + d.Name + " (password hidden)", d.EnvKey + "=" + redact(replaceHost(d.EnvVal, svc))},
			{"Then recreate the container", "docker compose up -d " + self},
		}
	}
	f.Logs, f.LogSource = p.Logs, p.LogSource
	return f
}

func startContainer(c *docker.Container) Fix {
	if c.Service != "" {
		cmd := "docker compose up -d " + c.Service
		if c.WorkingDir != "" {
			cmd = "cd " + c.WorkingDir + " && " + cmd
		}
		return Fix{"Start it again after fixing the cause", cmd}
	}
	return Fix{"Start it again after fixing the cause", "docker start " + c.Name}
}

func exitMeaning(code int) string {
	switch code {
	case 0:
		return "It exited cleanly (code 0): it was stopped (docker stop, compose stop) or its main process finished."
	case 137:
		return "Exit code 137: killed (SIGKILL), usually out of memory or `docker kill`."
	case 139:
		return "Exit code 139: segmentation fault."
	case 143:
		return "Exit code 143: stopped with SIGTERM (docker stop)."
	case 126, 127:
		return "Exit code " + strconv.Itoa(code) + ": the command couldn't be run (not found or not executable)."
	}
	return "The process crashed with exit code " + strconv.Itoa(code) + "."
}

func redact(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.User == nil {
		return v
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
		return strings.Replace(u.String(), "xxxxx", "***", 1)
	}
	return v
}

func replaceHost(v, host string) string {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return v
	}
	if p := u.Port(); p != "" {
		u.Host = host + ":" + p
	} else {
		u.Host = host
	}
	return u.String()
}

// Root picks the root cause. Walking from the request inward, a level whose
// findings are all symptoms (crash loops, 5xx, ...) defers to deeper findings;
// otherwise its most confident real failure wins.
func Root(fs []*Finding) (*Finding, []*Finding) {
	if len(fs) == 0 {
		return nil, nil
	}
	sorted := append([]*Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Depth != sorted[j].Depth {
			return sorted[i].Depth < sorted[j].Depth
		}
		return sorted[i].Confidence > sorted[j].Confidence
	})
	root := -1
	for i := 0; i < len(sorted); {
		j := i
		for j < len(sorted) && sorted[j].Depth == sorted[i].Depth {
			j++
		}
		for k := i; k < j; k++ {
			if !sorted[k].Symptom {
				root = k
				break
			}
		}
		if root >= 0 {
			break
		}
		if j == len(sorted) {
			root = i
		}
		i = j
	}
	others := append(append([]*Finding(nil), sorted[:root]...), sorted[root+1:]...)
	return sorted[root], others
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

func joinInts(list []int) string {
	var s []string
	for _, n := range list {
		s = append(s, strconv.Itoa(n))
	}
	return strings.Join(s, ", ")
}

func firstOr(list []string, def string) string {
	if len(list) > 0 {
		return list[0]
	}
	return def
}

func portOf(ports []compose.Port, host int) int {
	for _, p := range ports {
		if p.Host == host {
			return p.Container
		}
	}
	return host
}

func shortPath(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func listenersCmd(port int) string {
	if runtime.GOOS == "linux" {
		return "ss -ltnp 'sport = :" + strconv.Itoa(port) + "'"
	}
	return "lsof -nP -iTCP:" + strconv.Itoa(port) + " -sTCP:LISTEN"
}
