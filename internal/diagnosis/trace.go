package diagnosis

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/collector/docker"
	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/nginx"
)

type Step struct {
	Status Status
	Text   string
	Detail string
	Pos    string
	Indent int
}

type Report struct {
	Target  Target
	Steps   []Step
	Root    *Finding
	Others  []*Finding
	Summary string
}

func (r *Report) OK() bool { return r.Root == nil }

func (e *Env) Diagnose(t Target) *Report {
	cfg, _ := e.Nginx()
	if cfg != nil {
		if r := e.traceNginx(cfg, t); r != nil {
			return r
		}
	}
	r := e.direct(t)
	if cfg != nil && r.Root != nil && !t.PortGiven {
		r.Root.Fixes = append(e.otherNginxPorts(cfg, t), r.Root.Fixes...)
	}
	return r
}

func pathArg(p string) string {
	if p == "/" {
		return ""
	}
	return p
}

// otherNginxPorts points at the ports nginx really serves this name on, e.g. a container published on :8088.
func (e *Env) otherNginxPorts(cfg *nginx.Config, t Target) []Fix {
	var out []Fix
	seen := map[int]bool{t.Port: true}
	for _, s := range cfg.Servers {
		if !slices.Contains(s.Names, hostForMatch(t.Host)) {
			continue
		}
		for _, l := range s.Listens {
			if l.Unix != "" {
				continue
			}
			port := dialPortFor(cfg, e, l.Port)
			if !seen[port] {
				seen[port] = true
				out = append(out, Fix{fmt.Sprintf("nginx serves %s on port %d; trace that instead", t.Host, port), fmt.Sprintf("waypoint %s:%d%s", t.Host, port, pathArg(t.Path))})
			}
		}
	}
	return out
}

var nonHTTPPorts = map[int]bool{22: true, 25: true, 53: true, 3306: true, 5432: true, 6379: true, 27017: true, 5672: true, 9092: true, 11211: true, 2181: true, 4222: true}

func (e *Env) direct(t Target) *Report {
	r := &Report{Target: t}
	p := e.ProbeEndpoint(nginx.Endpoint{Host: t.Host, Port: t.Port}, nil)
	if p.TCP.OK() && (t.Scheme != "" || !nonHTTPPorts[t.Port]) {
		p.HTTP = e.httpProbe(t, "")
	}
	r.Steps = probeSteps(p, 0)
	e.finish(r, e.Analyze(p))
	if r.OK() {
		r.Summary = fmt.Sprintf("%s is up", t.HostPort())
		if owner := p.OwnerLabel(); owner != "" {
			r.Summary += " (" + owner + ")"
		}
		if p.HTTP != nil && p.HTTP.OK() {
			r.Summary += fmt.Sprintf(", HTTP %d in %s", p.HTTP.Status, p.HTTP.Took.Round(1e6))
		}
	}
	return r
}

func (e *Env) httpProbe(t Target, connect string) *network.HTTPResult {
	if t.Scheme != "" {
		h := network.HTTPGet(e.Ctx, t.URL(), connect, e.Timeout)
		return &h
	}
	h := network.HTTPGet(e.Ctx, t.URL(), connect, e.Timeout)
	if h.OK() || !strings.Contains(h.Err, "malformed HTTP") && !strings.Contains(h.Err, "HTTP response to HTTPS") {
		return &h
	}
	t.Scheme = "https"
	hs := network.HTTPGet(e.Ctx, t.URL(), connect, e.Timeout)
	if hs.OK() {
		return &hs
	}
	return nil // not an HTTP service
}

func (e *Env) finish(r *Report, fs []*Finding) {
	r.Root, r.Others = Root(fs)
}

func probeSteps(p *Probe, indent int) []Step {
	var s []Step
	if p.DNS.Class != "" && !p.DNS.OK() {
		return append(s, Step{Status: Fail, Text: "DNS " + p.Host, Detail: p.DNS.Err, Indent: indent})
	}
	addr := p.Addr()
	if p.Via != nil {
		addr += " (from " + p.Via.DisplayName() + ")"
	}
	st := Step{Status: Pass, Text: addr, Indent: indent}
	switch {
	case p.TCP.Class == network.Unknown:
		st.Status, st.Detail = Warn, p.TCP.Err
	case !p.TCP.OK():
		st.Status, st.Detail = Fail, p.TCP.Err
	}
	if owner := p.OwnerLabel(); owner != "" {
		st.Detail = joinDetail(owner, stateOf(p), st.Detail)
	}
	if st.Status == Pass && !p.Up() {
		st.Status = Fail
	}
	s = append(s, st)
	if p.HTTP != nil {
		hs := Step{Status: Pass, Text: "HTTP", Indent: indent + 1}
		switch {
		case !p.HTTP.OK():
			hs.Status, hs.Detail = Fail, p.HTTP.Err
		default:
			hs.Detail = httpText(p.HTTP)
			if p.HTTP.Status >= 500 {
				hs.Status = Fail
			}
		}
		s = append(s, hs)
	}
	for _, d := range p.Deps {
		if d.Probe == nil {
			continue
		}
		ds := probeSteps(d.Probe, indent+1)
		if network.IsLocal(d.Name) && p.Container != nil && !d.Probe.TCP.OK() && len(ds) > 0 {
			ds[0].Status, ds[0].Detail = Fail, "localhost here is the "+p.Container.DisplayName()+" container itself"
		}
		if d.EnvKey != "" && len(ds) > 0 {
			ds[0].Detail = joinDetail(ds[0].Detail, "via "+d.EnvKey)
		}
		s = append(s, ds...)
	}
	return s
}

func stateOf(p *Probe) string {
	if p.Container != nil && p.Container.StateText() != "running" {
		return p.Container.StateText()
	}
	for _, u := range p.Units {
		if u.Down() {
			return u.StateText()
		}
	}
	return ""
}

func httpText(h *network.HTTPResult) string {
	s := strconv.Itoa(h.Status) + " " + http.StatusText(h.Status)
	if h.Location != "" {
		s += " → " + h.Location
	}
	return s
}

func joinDetail(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " · ")
}

func (e *Env) nginxEntry(cfg *nginx.Config, t Target) (m *nginx.Match, listenPort, dialPort int, ok bool) {
	listenPort, dialPort = t.Port, t.Port
	if cfg.Container != "" {
		c := e.Docker().ByName(cfg.Container, nil)
		if c == nil {
			return nil, 0, 0, false
		}
		found := false
		for _, b := range c.Bindings {
			if network.IsLocal(t.Host) && b.HostPort == t.Port || !network.IsLocal(t.Host) && b.ContainerPort == t.Port {
				listenPort, dialPort, found = b.ContainerPort, b.HostPort, true
				break
			}
		}
		if !found {
			return nil, 0, 0, false
		}
	}
	if !t.PortGiven && t.Scheme == "" && !network.IsLocal(t.Host) {
		if m := cfg.Route(t.Host, 443, t.pathOnly()); m != nil && named(m) {
			return m, 443, dialPortFor(cfg, e, 443), true
		}
	}
	m = cfg.Route(hostForMatch(t.Host), listenPort, t.pathOnly())
	if m == nil {
		return nil, 0, 0, false
	}
	if !network.IsLocal(t.Host) && !named(m) {
		return nil, 0, 0, false
	}
	return m, listenPort, dialPort, true
}

func dialPortFor(cfg *nginx.Config, e *Env, listen int) int {
	if cfg.Container == "" {
		return listen
	}
	if c := e.Docker().ByName(cfg.Container, nil); c != nil {
		for _, b := range c.Bindings {
			if b.ContainerPort == listen {
				return b.HostPort
			}
		}
	}
	return listen
}

func named(m *nginx.Match) bool {
	switch m.ServerReason {
	case "exact name", "wildcard name", "regex name":
		return true
	}
	return false
}

func hostForMatch(h string) string {
	if h == "127.0.0.1" || h == "::1" {
		return "localhost"
	}
	return h
}

func (e *Env) nginxContainer(cfg *nginx.Config) *docker.Container {
	if cfg.Container == "" {
		return nil
	}
	return e.Docker().ByName(cfg.Container, nil)
}

func (e *Env) traceNginx(cfg *nginx.Config, t Target) *Report {
	m, listenPort, dialPort, ok := e.nginxEntry(cfg, t)
	if !ok {
		return nil
	}
	r := &Report{Target: t}
	ssl := false
	for _, l := range m.Server.Listens {
		if l.Port == listenPort && l.SSL {
			ssl = true
		}
	}
	nc := e.nginxContainer(cfg)
	where := "nginx"
	if nc != nil {
		where = "nginx (" + nc.Label() + ")"
	}
	listener := network.DialTCP(e.Ctx, "127.0.0.1", dialPort, e.Timeout)
	ls := Step{Status: Pass, Text: fmt.Sprintf("%s listening on :%d", where, dialPort)}
	if !listener.OK() {
		ls.Status, ls.Detail = Fail, listener.Err
	}
	r.Steps = append(r.Steps, ls)

	var fs []*Finding
	var resp *network.HTTPResult
	if listener.OK() {
		ht := Target{Scheme: "http", Host: t.Host, Port: dialPort, Path: t.Path}
		if ssl {
			ht.Scheme = "https"
		}
		h := network.HTTPGet(e.Ctx, ht.URL(), "127.0.0.1", e.Timeout)
		resp = &h
		hs := Step{Status: Pass, Text: "HTTP " + ht.URL(), Indent: 1}
		if !h.OK() {
			hs.Status, hs.Detail = Fail, h.Err
		} else {
			hs.Detail = httpText(&h)
			if h.Status >= 500 {
				hs.Status = Fail
			}
		}
		r.Steps = append(r.Steps, hs)
		if ssl {
			if f, st := e.certCheck(t.Host, dialPort, m.Server); st != nil {
				r.Steps = append(r.Steps, *st)
				if f != nil {
					fs = append(fs, f)
				}
			}
		}
	} else {
		fs = append(fs, e.nginxDown(cfg, nc, dialPort))
	}

	r.Steps = append(r.Steps, Step{Status: Pass, Text: "server " + m.Server.DisplayName(), Detail: m.ServerReason, Pos: shortPos(m.Server.Pos)})
	switch {
	case m.Location == nil && m.Server.Return != nil:
		ret := m.Server.Return
		r.Steps = append(r.Steps, Step{Status: Info, Text: fmt.Sprintf("return %d %s", ret.Code, ret.URL), Indent: 1})
	case m.Location == nil:
		r.Steps = append(r.Steps, Step{Status: Fail, Text: "no location matches " + t.pathOnly(), Indent: 1})
		fs = append(fs, &Finding{
			Title:      fmt.Sprintf("no location in %s matches %s", m.Server.DisplayName(), t.pathOnly()),
			Detail:     "nginx has nothing to serve for this path and answers 404.",
			Confidence: 0.7,
			Evidence:   []Evidence{pass("server %s (%s)", m.Server.DisplayName(), shortPos(m.Server.Pos)), fail("none of its locations match %s", t.pathOnly())},
			Fixes:      []Fix{{"Add a location for this path, or a catch-all `location /`, in " + shortPos(m.Server.Pos), ""}},
		})
	default:
		loc := m.Location
		r.Steps = append(r.Steps, Step{Status: Pass, Text: "location " + loc.String(), Pos: shortPos(loc.Pos), Indent: 1})
		steps, more := e.locationTarget(cfg, nc, loc, 2)
		r.Steps = append(r.Steps, steps...)
		fs = append(fs, more...)
		if resp != nil && resp.OK() && resp.Status >= 500 && len(more) == 0 {
			fs = append(fs, e.nginx5xx(cfg, nc, resp, loc))
		}
	}
	e.finish(r, fs)
	// A failing nginx -t matters for the next reload, not for whether this request works now.
	if f := e.testFailure(cfg); f != nil && listener.OK() {
		r.Others = append(r.Others, f)
	}
	if r.OK() {
		r.Summary = t.Host + t.Path + " → nginx"
		if m.Location != nil {
			r.Summary += " " + m.Location.String() + " → " + m.Location.Target()
		}
		if resp != nil && resp.OK() {
			r.Summary += fmt.Sprintf(" · HTTP %d", resp.Status)
		}
	}
	return r
}

func (e *Env) locationTarget(cfg *nginx.Config, nc *docker.Container, loc *nginx.Location, indent int) ([]Step, []*Finding) {
	var steps []Step
	var fs []*Finding
	switch loc.Kind {
	case nginx.KindProxy, nginx.KindFastCGI:
		u := loc.Upstream
		head := Step{Status: Pass, Text: u.Directive + " " + u.Raw, Indent: indent}
		if u.Dynamic {
			head.Status, head.Detail = Warn, "uses variables, resolved per request; not checked"
			return append(steps, head), nil
		}
		if len(u.Endpoints) == 0 {
			head.Status, head.Detail = Warn, "upstream "+u.Name+" has no servers"
			return append(steps, head), nil
		}
		headIdx := len(steps)
		steps = append(steps, head)
		up := 0
		for _, ep := range u.Endpoints {
			p := e.ProbeEndpoint(ep, nc)
			if p.Up() {
				up++
			}
			steps = append(steps, probeSteps(p, indent+1)...)
			for _, f := range e.Analyze(p) {
				f.Depth++
				fs = append(fs, f)
			}
		}
		if up == 0 {
			steps[headIdx].Status = Fail
		} else if up < len(u.Endpoints) {
			// nginx keeps serving from the healthy servers; report but don't fail the route.
			for _, f := range fs {
				f.Confidence *= 0.5
				f.Title += " (other upstream servers are up)"
			}
		}
	case nginx.KindStatic:
		ok, detail := e.dirExists(nc, loc.Root)
		st := Step{Status: Pass, Text: "files " + loc.Root, Detail: detail, Indent: indent}
		if !ok {
			st.Status = Fail
			fs = append(fs, &Finding{
				Title:      "nginx serves files from " + loc.Root + ", which doesn't exist",
				Detail:     "Requests here return 404. The directory was moved, never deployed, or the path has a typo.",
				Confidence: 0.85,
				Evidence:   []Evidence{fail("%s: %s", loc.Root, detail)},
				Fixes:      []Fix{{"Check the path in " + shortPos(loc.Pos), "ls -ld " + loc.Root}},
			})
		}
		steps = append(steps, st)
	case nginx.KindRedirect:
		steps = append(steps, Step{Status: Info, Text: "redirect " + loc.Target(), Indent: indent})
	case nginx.KindReturn:
		steps = append(steps, Step{Status: Info, Text: loc.Target(), Indent: indent})
	default:
		steps = append(steps, Step{Status: Warn, Text: "no proxy_pass, root or return here", Indent: indent})
	}
	return steps, fs
}

func (e *Env) dirExists(nc *docker.Container, dir string) (bool, string) {
	if strings.Contains(dir, "$") {
		return true, "uses variables; not checked"
	}
	if nc != nil {
		if _, err := e.Runner.Run(e.Ctx, "docker", "exec", nc.Name, "test", "-d", dir); err != nil {
			return false, "not found in " + nc.Name
		}
		return true, "exists in " + nc.Name
	}
	fi, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		return false, "no such directory"
	case os.IsPermission(err):
		return true, "exists (no permission to read)"
	case err != nil:
		return false, err.Error()
	case !fi.IsDir():
		return true, "is a file"
	}
	return true, "directory exists"
}

func (e *Env) certCheck(host string, port int, s *nginx.Server) (*Finding, *Step) {
	sni := host
	if network.IsLocal(host) {
		sni = s.DisplayName()
	}
	cert, err := network.CertInfo(e.Ctx, "127.0.0.1", port, sni, e.Timeout)
	if err != nil && s.Cert != "" {
		cert, err = network.CertFile(s.Cert, sni)
	}
	if err != nil {
		return nil, &Step{Status: Warn, Text: "certificate", Detail: "could not read: " + err.Error(), Indent: 1}
	}
	return certFinding(cert, sni, s)
}

func certFinding(cert *network.Cert, name string, s *nginx.Server) (*Finding, *Step) {
	days := cert.DaysLeft()
	st := &Step{Status: Pass, Text: "certificate", Detail: fmt.Sprintf("%s, %d days left", cert.Issuer, days), Indent: 1}
	var f *Finding
	switch {
	case days < 0:
		st.Status, st.Detail = Fail, fmt.Sprintf("expired %s", cert.NotAfter.Format("2006-01-02"))
		f = &Finding{Title: "the certificate for " + name + " has expired", Confidence: 0.95,
			Detail:   "Browsers block the site. If you use Let's Encrypt, renewal is failing.",
			Evidence: []Evidence{fail("expired on %s", cert.NotAfter.Format("2006-01-02"))},
			Fixes:    []Fix{{"Renew (Let's Encrypt)", "sudo certbot renew && sudo systemctl reload nginx"}}}
	case !cert.NameOK:
		st.Status, st.Detail = Fail, "doesn't cover "+name
		f = &Finding{Title: "the certificate served for " + name + " is for " + cert.Subject, Confidence: 0.9,
			Detail:   "Visitors get a name mismatch error. nginx is likely using another server's certificate.",
			Evidence: []Evidence{fail("certificate subject %s", cert.Subject)},
			Fixes:    []Fix{{"Check ssl_certificate in " + shortPos(s.Pos), ""}}}
	case days < 14:
		st.Status = Warn
		f = &Finding{Title: fmt.Sprintf("the certificate for %s expires in %d days", name, days), Confidence: 0.5,
			Evidence: []Evidence{warn("expires %s", cert.NotAfter.Format("2006-01-02"))},
			Fixes:    []Fix{{"Test renewal", "sudo certbot renew --dry-run"}}}
	}
	return f, st
}

func (e *Env) nginxDown(cfg *nginx.Config, nc *docker.Container, port int) *Finding {
	if nc != nil {
		p := &Probe{Host: "127.0.0.1", Port: port, Container: nc, TCP: network.Result{Class: network.Refused}}
		e.collectLogs(p)
		if f := e.rule(p); f != nil {
			f.Logs, f.LogSource = p.Logs, p.LogSource
			return f
		}
	}
	f := &Finding{
		Title:      fmt.Sprintf("nginx is not listening on :%d", port),
		Confidence: 0.85,
		Evidence:   []Evidence{fail("connect 127.0.0.1:%d: refused", port)},
	}
	if cfg.Container == "" && e.Runner.Has("nginx") {
		out, err := e.Runner.Combined(e.Ctx, "nginx", "-t")
		if err != nil {
			if line := nginx.EmergError(out); line != "" {
				f.Title = "nginx can't start: its configuration is invalid"
				f.Detail = line
				f.Confidence = 0.95
				f.Evidence = append(f.Evidence, fail("nginx -t: %s", line))
				f.Fixes = []Fix{{"Fix the line above, then", "sudo nginx -t && sudo systemctl restart nginx"}}
				return f
			}
		} else {
			f.Evidence = append(f.Evidence, pass("nginx -t: configuration is valid"))
		}
	}
	if u := e.Systemd().Status(e.Ctx, "nginx.service"); u != nil {
		f.Evidence = append(f.Evidence, fail("nginx.service: %s", u.StateText()))
		lines, _ := e.Systemd().Logs(e.Ctx, "nginx.service", 8)
		f.Logs, f.LogSource = lines, "journalctl -u nginx.service"
		f.Fixes = []Fix{{"Start it", "sudo systemctl start nginx"}, {"Logs", "journalctl -u nginx -n 50 --no-pager"}}
		return f
	}
	f.Fixes = []Fix{{"Start it", "sudo nginx   # or: brew services start nginx"}}
	return f
}

func (e *Env) testFailure(cfg *nginx.Config) *Finding {
	if cfg.TestError == "" {
		return nil
	}
	cmd := "sudo nginx -t"
	if cfg.Container != "" {
		cmd = "docker exec " + cfg.Container + " nginx -t"
	}
	f := &Finding{
		Title:      "nginx config test fails: " + cfg.TestError,
		Detail:     "A running nginx keeps serving its old config, but it will refuse to reload or restart with this one.",
		Confidence: 0.7,
		Symptom:    strings.Contains(cfg.TestError, "host not found in upstream"),
		Evidence:   []Evidence{fail("nginx -t: %s", cfg.TestError)},
		Fixes:      []Fix{{"Re-run the test after fixing", cmd}},
	}
	// Docker DNS only knows a container while it runs, so a down upstream also breaks nginx -t.
	if m := upstreamHost.FindStringSubmatch(cfg.TestError); m != nil {
		if nc := e.nginxContainer(cfg); nc != nil {
			snap := e.Docker()
			c := snap.ByService(nc.Project, m[1])
			if c == nil {
				c = snap.ByName(m[1], nc.NetworkNames())
			}
			if c != nil && !c.Running() {
				f.Title = fmt.Sprintf("nginx can't reload or restart while %s is down", m[1])
				f.Detail = fmt.Sprintf("Docker resolves the name %s only while that container runs. nginx -t passes again once %s is up.", m[1], m[1])
				f.Evidence = append(f.Evidence, fail("%s: %s", c.Name, c.StateText()))
				f.Confidence = 0.5
			}
		}
	}
	return f
}

var upstreamHost = regexp.MustCompile(`host not found in upstream "([^":/]+)`)

func (e *Env) nginx5xx(cfg *nginx.Config, nc *docker.Container, h *network.HTTPResult, loc *nginx.Location) *Finding {
	f := &Finding{
		Title:      fmt.Sprintf("nginx returns %d for %s", h.Status, loc.String()),
		Confidence: 0.6,
		Symptom:    true,
		Evidence:   []Evidence{pass("nginx is up"), fail("HTTP %d %s", h.Status, http.StatusText(h.Status))},
	}
	if loc.Upstream != nil && (h.Status == 502 || h.Status == 504) {
		f.Detail = "The upstream accepts connections from here but nginx still fails: it may be timing out, " +
			"closing the connection, or speaking a different protocol (http vs https)."
	} else {
		f.Detail = "The app behind nginx answered with a server error; its logs will say why."
	}
	if nc != nil {
		out, _ := e.Runner.Combined(e.Ctx, "docker", "logs", "--tail", "8", nc.Name)
		f.Logs, f.LogSource = lastLines(out, 8), "docker logs "+nc.Name
	} else if lines := tailFile("/var/log/nginx/error.log", 8); len(lines) > 0 {
		f.Logs, f.LogSource = lines, "/var/log/nginx/error.log"
	}
	return f
}

func tailFile(path string, n int) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(b) > 64<<10 {
		b = b[len(b)-64<<10:]
	}
	return lastLines(string(b), n)
}

func shortPos(pos string) string {
	for _, prefix := range []string{"/etc/nginx/", "/usr/local/etc/nginx/", "/opt/homebrew/etc/nginx/"} {
		if s, ok := strings.CutPrefix(pos, prefix); ok {
			return s
		}
	}
	return pos
}
