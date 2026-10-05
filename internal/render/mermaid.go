package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/diagnosis"
)

type graph struct {
	ids     map[string]string
	lines   []string
	edges   []string
	classes []string
}

func (g *graph) node(key string, st diagnosis.Status) (string, bool) {
	if id, ok := g.ids[key]; ok {
		return id, false
	}
	id := fmt.Sprintf("n%d", len(g.ids))
	g.ids[key] = id
	g.classes = append(g.classes, fmt.Sprintf("  class %s %s", id, class(st)))
	return id, true
}

func (g *graph) add(indent, id, label string) {
	g.lines = append(g.lines, fmt.Sprintf("%s%s[\"%s\"]", indent, id, esc(label)))
}

// Mermaid draws visitors → nginx sites → apps (grouped by how they run) → dependencies.
func Mermaid(w io.Writer, r *diagnosis.MapReport, inv *diagnosis.Inventory) {
	g := &graph{ids: map[string]string{}}
	used := map[*diagnosis.App]bool{}

	target := func(pr *diagnosis.Probe) string {
		a, svc := inv.AppOf(pr)
		if a == nil {
			st := diagnosis.Pass
			if !pr.Up() {
				st = diagnosis.Fail
			}
			id, isNew := g.node("ep|"+pr.Addr(), st)
			if isNew {
				label := pr.Addr()
				switch {
				case pr.Unix == "" && !network.IsLocal(pr.Host) && pr.Via == nil:
					label += "<br/>another machine"
					if !pr.Up() {
						label += " · unreachable"
					}
				case !pr.Up():
					label += "<br/>nothing running"
				}
				g.add("  ", id, label)
			}
			return id
		}
		used[a] = true
		if svc != nil && a.Kind == "docker compose" {
			id, _ := g.node("svc|"+a.Name+"|"+svc.Name, svc.Status)
			return id
		}
		id, _ := g.node("app|"+a.Name, a.Status)
		return id
	}

	if r != nil {
		g.lines = append(g.lines, "  visitors((visitors))", "  subgraph nginx[\"nginx\"]")
		for _, s := range r.Servers {
			if s.Server.Ignored() {
				continue
			}
			st := diagnosis.Pass
			if s.Cert != nil && s.Cert.Status != diagnosis.Pass {
				st = s.Cert.Status
			}
			id, _ := g.node("site|"+s.Server.Pos, st)
			g.add("    ", id, s.Server.DisplayName()+"<br/>"+s.Server.ListenSummary())
			g.edges = append(g.edges, "  visitors --> "+id)
		}
		g.lines = append(g.lines, "  end")
		for _, s := range r.Servers {
			if s.Server.Ignored() {
				continue
			}
			sid := g.ids["site|"+s.Server.Pos]
			for _, e := range s.Entries {
				path := locText(e)
				if len(e.Probes) == 0 {
					label := e.Target
					if e.Location != nil && e.Location.Root != "" {
						label = "files " + e.Location.Root
					}
					tid, isNew := g.node("ep|"+label, e.Status)
					if isNew {
						g.add("  ", tid, label)
					}
					g.edges = append(g.edges, fmt.Sprintf("  %s -- \"%s\" --> %s", sid, esc(path), tid))
					continue
				}
				for _, pr := range e.Probes {
					tid := target(pr)
					g.edges = append(g.edges, fmt.Sprintf("  %s -- \"%s\" --> %s", sid, esc(path), tid))
					for _, d := range pr.Deps {
						if d.Probe == nil {
							continue
						}
						edge := fmt.Sprintf("  %s -.-> %s", tid, target(d.Probe))
						if !contains(g.edges, edge) {
							g.edges = append(g.edges, edge)
						}
					}
				}
			}
		}
	}

	if inv != nil {
		var unrouted []*diagnosis.App
		for _, a := range inv.Apps {
			if r != nil && !used[a] {
				unrouted = append(unrouted, a)
				continue
			}
			appGraph(g, a, "  ")
		}
		if len(unrouted) > 0 {
			g.lines = append(g.lines, "  subgraph unrouted[\"not behind nginx\"]")
			for _, a := range unrouted {
				appGraph(g, a, "    ")
			}
			g.lines = append(g.lines, "  end")
		}
	}

	fmt.Fprintln(w, "```mermaid")
	fmt.Fprintln(w, "flowchart LR")
	for _, l := range append(append(g.lines, g.edges...), g.classes...) {
		fmt.Fprintln(w, l)
	}
	fmt.Fprintln(w, "  classDef ok stroke:#2da44e,stroke-width:2px")
	fmt.Fprintln(w, "  classDef bad stroke:#cf222e,stroke-width:2px,color:#cf222e")
	fmt.Fprintln(w, "  classDef warn stroke:#bf8700,stroke-width:2px")
	fmt.Fprintln(w, "  classDef info stroke:#8c959f")
	fmt.Fprintln(w, "```")
}

func appGraph(g *graph, a *diagnosis.App, indent string) {
	if a.Kind == "docker compose" {
		g.lines = append(g.lines, fmt.Sprintf("%ssubgraph %s[\"%s\"]", indent, safeID("compose_"+a.Name), esc(a.Name+" · docker compose")))
		for _, s := range a.Services {
			id, _ := g.node("svc|"+a.Name+"|"+s.Name, s.Status)
			g.add(indent+"  ", id, s.Name+portsLine(s.Ports)+"<br/>"+s.State)
		}
		g.lines = append(g.lines, indent+"end")
		return
	}
	id, _ := g.node("app|"+a.Name, a.Status)
	label := a.Name + portsLine(a.Ports) + "<br/>" + a.Kind
	for _, f := range a.Facts {
		if f.Label == "folder" || f.Label == "image" {
			label += "<br/>" + f.Value
		}
	}
	g.add(indent, id, label+"<br/>"+a.State)
}

func portsLine(ports []diagnosis.AppPort) string {
	var s []string
	for _, p := range ports {
		if p.Port != 0 {
			s = append(s, fmt.Sprintf(":%d", p.Port))
		}
	}
	if len(s) == 0 {
		return ""
	}
	return " " + strings.Join(s, " ")
}

func safeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func class(s diagnosis.Status) string {
	switch s {
	case diagnosis.Pass:
		return "ok"
	case diagnosis.Fail:
		return "bad"
	case diagnosis.Warn:
		return "warn"
	}
	return "info"
}

func esc(s string) string {
	parts := strings.Split(s, "<br/>")
	r := strings.NewReplacer(`"`, "#quot;", "<", "#lt;", ">", "#gt;")
	for i := range parts {
		parts[i] = r.Replace(parts[i])
	}
	return strings.Join(parts, "<br/>")
}
