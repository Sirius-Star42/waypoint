package diagnosis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/nginx"
)

type MapReport struct {
	Config  *nginx.Config
	Servers []*MapServer
	Issues  []*Finding
	Down    []int
	// Published maps nginx's container ports to host ports when nginx runs in Docker.
	Published map[int]int
}

type MapServer struct {
	Server  *nginx.Server
	Cert    *Step
	Entries []*MapEntry
}

type MapEntry struct {
	Location *nginx.Location
	Nested   int
	Status   Status
	Target   string
	Detail   string
	Sub      []Step
	Probes   []*Probe
}

func (e *Env) Map() (*MapReport, error) {
	cfg, err := e.Nginx()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	r := &MapReport{Config: cfg, Published: map[int]int{}}
	nc := e.nginxContainer(cfg)
	if nc != nil {
		for _, b := range nc.Bindings {
			r.Published[b.ContainerPort] = b.HostPort
		}
	}
	up := map[int]bool{}
	for _, s := range cfg.Servers {
		for _, l := range s.Listens {
			if l.Unix != "" {
				continue
			}
			if _, done := up[l.Port]; done {
				continue
			}
			up[l.Port] = network.DialTCP(e.Ctx, "127.0.0.1", dialPortFor(cfg, e, l.Port), e.Timeout).OK()
			if !up[l.Port] {
				r.Down = append(r.Down, l.Port)
			}
		}
	}
	sort.Ints(r.Down)
	var down *Finding
	if len(r.Down) > 0 {
		down = e.nginxDown(cfg, nc, dialPortFor(cfg, e, r.Down[0]))
		r.Issues = append(r.Issues, down)
	}

	seen := map[*Probe]bool{}
	for _, s := range sortedServers(cfg.Servers) {
		ms := &MapServer{Server: s}
		r.Servers = append(r.Servers, ms)
		if s.Ignored() {
			continue
		}
		if s.Return != nil {
			ms.Entries = append(ms.Entries, &MapEntry{Status: Info, Target: fmt.Sprintf("%d %s", s.Return.Code, s.Return.URL)})
			continue
		}
		if port, ok := sslPort(s); ok && s.DisplayName() != "(default)" && !strings.ContainsAny(s.DisplayName(), "*~") {
			var f *Finding
			if up[port] {
				f, ms.Cert = e.certCheck(s.DisplayName(), dialPortFor(cfg, e, port), s)
			} else if s.Cert != "" {
				if cert, err := network.CertFile(s.Cert, s.DisplayName()); err == nil {
					f, ms.Cert = certFinding(cert, s.DisplayName(), s)
				}
			}
			if f != nil {
				r.Issues = append(r.Issues, f)
			}
		}
		e.mapLocations(r, ms, s.Locations, 0, seen)
	}
	if f := testFailure(cfg); f != nil && len(r.Down) == 0 {
		r.Issues = append(r.Issues, f)
	}
	for _, c := range cfg.Conflicts {
		r.Issues = append(r.Issues, &Finding{
			Title:      fmt.Sprintf("%s is defined twice on port %d; nginx ignores the second one", c.Name, c.Port),
			Detail:     "nginx only warns about this at startup. Changes made in the ignored block have no effect.",
			Confidence: 0.9,
			Evidence:   []Evidence{pass("used: %s", shortPos(c.Used)), fail("ignored: %s", shortPos(c.Ignored))},
			Fixes:      []Fix{{"Remove or merge the duplicate server block", ""}},
		})
	}
	sort.SliceStable(r.Issues, func(i, j int) bool { return r.Issues[i].Confidence > r.Issues[j].Confidence })
	if len(r.Down) > 0 {
		for i, f := range r.Issues {
			if f == down {
				copy(r.Issues[1:i+1], r.Issues[:i])
				r.Issues[0] = down
				break
			}
		}
	}
	return r, nil
}

func (e *Env) mapLocations(r *MapReport, ms *MapServer, locs []*nginx.Location, nested int, seen map[*Probe]bool) {
	nc := e.nginxContainer(r.Config)
	for _, loc := range locs {
		me := &MapEntry{Location: loc, Nested: nested, Status: Pass, Target: loc.Target()}
		ms.Entries = append(ms.Entries, me)
		switch loc.Kind {
		case nginx.KindProxy, nginx.KindFastCGI:
			u := loc.Upstream
			if u.Dynamic {
				me.Status, me.Detail = Warn, "variables, not checked"
				break
			}
			var probes []*Probe
			for _, ep := range u.Endpoints {
				probes = append(probes, e.ProbeEndpoint(ep, nc))
			}
			me.Probes = probes
			if len(probes) == 1 {
				p := probes[0]
				me.Status, me.Detail = probeStatus(p)
				me.Sub = depSteps(p)
			} else {
				upCount := 0
				for _, p := range probes {
					st, d := probeStatus(p)
					if st == Pass {
						upCount++
					}
					me.Sub = append(me.Sub, Step{Status: st, Text: p.Addr(), Detail: d})
				}
				switch {
				case len(probes) == 0:
					me.Status, me.Detail = Warn, "upstream has no servers"
				case upCount == 0:
					me.Status = Fail
				case upCount < len(probes):
					me.Status, me.Detail = Warn, fmt.Sprintf("%d of %d servers up", upCount, len(probes))
				}
			}
			for _, p := range probes {
				if seen[p] {
					continue
				}
				seen[p] = true
				if root, _ := Root(e.Analyze(p)); root != nil {
					root.Title = fmt.Sprintf("%s %s → %s", ms.Server.DisplayName(), loc.String(), root.Title)
					r.Issues = append(r.Issues, root)
				}
			}
		case nginx.KindStatic:
			ok, detail := e.dirExists(nc, loc.Root)
			me.Detail = detail
			if !ok {
				me.Status = Fail
				r.Issues = append(r.Issues, &Finding{
					Title:      fmt.Sprintf("%s %s → %s doesn't exist", ms.Server.DisplayName(), loc.String(), loc.Root),
					Confidence: 0.85,
					Evidence:   []Evidence{fail("%s: %s", loc.Root, detail)},
					Fixes:      []Fix{{"Fix the path in " + shortPos(loc.Pos), "ls -ld " + loc.Root}},
				})
			}
		case nginx.KindRedirect, nginx.KindReturn:
			me.Status = Info
		default:
			me.Status = Info
		}
		e.mapLocations(r, ms, loc.Children, nested+1, seen)
	}
}

func probeStatus(p *Probe) (Status, string) {
	owner := p.OwnerLabel()
	switch {
	case p.DNS.Class != "" && !p.DNS.OK():
		return Fail, "does not resolve"
	case p.TCP.Class == network.Unknown && (p.Container == nil || p.Container.Running()):
		return Warn, joinDetail(owner, "not checked")
	case !p.Up():
		reason := stateOf(p)
		if reason == "" {
			switch p.TCP.Class {
			case network.Refused:
				reason = "nothing listening"
			case network.NoSuchHost:
				reason = "can't resolve " + p.Host
			default:
				reason = p.TCP.Err
			}
		}
		return Fail, joinDetail(owner, reason)
	}
	for _, d := range p.Deps {
		if d.Probe != nil && !d.Probe.Up() && d.Probe.TCP.Class != network.Unknown {
			return Warn, joinDetail(owner, "dependency "+d.Name+" is down")
		}
	}
	return Pass, owner
}

func depSteps(p *Probe) []Step {
	var out []Step
	for _, d := range p.Deps {
		if d.Probe == nil {
			continue
		}
		st, detail := probeStatus(d.Probe)
		if d.Probe.TCP.Class == network.Unknown && st == Warn {
			st = Info
		}
		text := d.Probe.Addr()
		if d.EnvKey != "" {
			detail = joinDetail(detail, "via "+d.EnvKey)
		}
		out = append(out, Step{Status: st, Text: text, Detail: detail})
	}
	return out
}

func sslPort(s *nginx.Server) (int, bool) {
	for _, l := range s.Listens {
		if l.SSL && l.Unix == "" {
			return l.Port, true
		}
	}
	return 0, false
}

func sortedServers(servers []*nginx.Server) []*nginx.Server {
	out := append([]*nginx.Server(nil), servers...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].DisplayName(), out[j].DisplayName()
		if (a == "(default)") != (b == "(default)") {
			return b == "(default)"
		}
		return a < b
	})
	return out
}
