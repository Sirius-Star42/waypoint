package render

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/diagnosis"
)

type shape struct{ open, close string }

var (
	box      = shape{"[", "]"}
	rounded  = shape{"(", ")"}
	stadium  = shape{"([", "])"}
	cylinder = shape{"[(", ")]"}
	folder   = shape{"[/", "/]"}
	hexagon  = shape{"{{", "}}"}
)

type graph struct {
	ids     map[string]string
	status  map[string]diagnosis.Status
	lines   []string
	edges   []string
	styles  []string
	classes []string
}

func (g *graph) node(key string, st diagnosis.Status) (string, bool) {
	if id, ok := g.ids[key]; ok {
		return id, false
	}
	id := fmt.Sprintf("n%d", len(g.ids))
	g.ids[key] = id
	g.status[id] = st
	g.classes = append(g.classes, fmt.Sprintf("  class %s %s", id, class(st)))
	return id, true
}

// add defines a node: a bold title over smaller detail lines, with ✗ or ! when it needs attention.
func (g *graph) add(indent, id string, sh shape, title string, details ...string) {
	switch g.status[id] {
	case diagnosis.Fail:
		title = "✗ " + title
	case diagnosis.Warn:
		title = "! " + title
	}
	label := "<b>" + esc(title) + "</b>"
	for _, d := range details {
		if d != "" {
			label += "<br/><small>" + esc(d) + "</small>"
		}
	}
	g.lines = append(g.lines, fmt.Sprintf("%s%s%s\"%s\"%s", indent, id, sh.open, label, sh.close))
}

// edge connects two nodes and colors the line by the health of the node it leads to.
func (g *graph) edge(from, to, label string, dotted bool) {
	var e string
	switch {
	case dotted && label != "":
		e = fmt.Sprintf("  %s -. \"%s\" .-> %s", from, esc(label), to)
	case dotted:
		e = fmt.Sprintf("  %s -.-> %s", from, to)
	case label != "":
		e = fmt.Sprintf("  %s -- \"%s\" --> %s", from, esc(label), to)
	default:
		e = fmt.Sprintf("  %s --> %s", from, to)
	}
	if contains(g.edges, e) {
		return
	}
	switch g.status[to] {
	case diagnosis.Fail:
		g.styles = append(g.styles, fmt.Sprintf("  linkStyle %d stroke:#cf222e,stroke-width:2px", len(g.edges)))
	case diagnosis.Warn:
		g.styles = append(g.styles, fmt.Sprintf("  linkStyle %d stroke:#bf8700,stroke-width:2px", len(g.edges)))
	}
	g.edges = append(g.edges, e)
}

// mermaidCode draws visitors → nginx sites → apps (grouped by how they run) → dependencies.
func mermaidCode(w io.Writer, r *diagnosis.MapReport, inv *diagnosis.Inventory) {
	g := &graph{ids: map[string]string{}, status: map[string]diagnosis.Status{}}
	used := map[*diagnosis.App]bool{}
	nginxContainer := ""
	if r != nil {
		nginxContainer = r.Config.Container
	}

	target := func(pr *diagnosis.Probe) string {
		a, svc := inv.AppOf(pr)
		if a == nil {
			st := diagnosis.Pass
			if !pr.Up() {
				st = diagnosis.Fail
			}
			id, isNew := g.node("ep|"+pr.Addr(), st)
			if isNew {
				sh, detail := box, ""
				switch {
				case pr.Unix == "" && !network.IsLocal(pr.Host) && pr.Via == nil:
					sh, detail = hexagon, "another machine"
					if !pr.Up() {
						detail += " · unreachable"
					}
				case !pr.Up():
					detail = "nothing running"
				}
				g.add("  ", id, sh, pr.Addr(), detail)
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

	// localhost inside a container is the container itself, so it gets its own node
	// instead of being merged with the host's localhost.
	dep := func(from string, pr *diagnosis.Probe, d *diagnosis.Dep) {
		if d.Probe == nil {
			return
		}
		if network.IsLocal(d.Name) && pr.Container != nil {
			st, detail := diagnosis.Warn, "inside the "+pr.Container.DisplayName()+" container"
			if !d.Probe.TCP.OK() {
				st, detail = diagnosis.Fail, detail+" · nothing listening"
			}
			id, isNew := g.node("ep|"+pr.Container.Name+"|"+d.Probe.Addr(), st)
			if isNew {
				g.add("  ", id, box, d.Probe.Addr(), detail)
			}
			g.edge(from, id, d.EnvKey, true)
			return
		}
		g.edge(from, target(d.Probe), d.EnvKey, true)
	}

	if r != nil {
		g.lines = append(g.lines, `  visitors(("<b>visitors</b>"))`)
		title := "nginx"
		if nginxContainer != "" {
			title += " · docker: " + nginxContainer
		}
		g.lines = append(g.lines, fmt.Sprintf("  subgraph nginx[\"%s\"]", esc(title)))
		for _, s := range r.Servers {
			if s.Server.Ignored() {
				continue
			}
			st := diagnosis.Pass
			if s.Cert != nil && s.Cert.Status != diagnosis.Pass {
				st = s.Cert.Status
			}
			id, _ := g.node("site|"+s.Server.Pos, st)
			g.add("    ", id, stadium, s.Server.DisplayName(), s.Server.ListenSummary()+published(r, s.Server))
		}
		g.lines = append(g.lines, "  end")
		for _, s := range r.Servers {
			if !s.Server.Ignored() {
				g.edge("visitors", g.ids["site|"+s.Server.Pos], "", false)
			}
		}
		for _, s := range r.Servers {
			if s.Server.Ignored() {
				continue
			}
			sid := g.ids["site|"+s.Server.Pos]
			for _, e := range s.Entries {
				path := locText(e)
				if len(e.Probes) == 0 {
					label, sh, detail := e.Target, box, ""
					if e.Location != nil && e.Location.Root != "" {
						label, sh, detail = e.Location.Root, folder, "static files"
						if e.Status == diagnosis.Fail {
							detail = "directory missing"
						}
					}
					tid, isNew := g.node("ep|"+label, e.Status)
					if isNew {
						g.add("  ", tid, sh, label, detail)
					}
					g.edge(sid, tid, path, false)
					continue
				}
				for _, pr := range e.Probes {
					tid := target(pr)
					g.edge(sid, tid, path, false)
					for _, d := range pr.Deps {
						dep(tid, pr, d)
					}
				}
			}
		}
	}

	if inv != nil {
		var unrouted, stopped []*diagnosis.App
		for _, a := range inv.Apps {
			switch {
			case a.Stopped && !used[a]:
				stopped = append(stopped, a)
			case r != nil && !used[a]:
				unrouted = append(unrouted, a)
			default:
				appGraph(g, a, "  ", nginxContainer)
			}
		}
		if len(unrouted) > 0 {
			g.lines = append(g.lines, `  subgraph unrouted["not behind nginx"]`)
			for _, a := range unrouted {
				appGraph(g, a, "    ", nginxContainer)
			}
			g.lines = append(g.lines, "  end")
			g.styles = append(g.styles, "  style unrouted fill:none,stroke:#8c959f,stroke-dasharray:4 3")
		}
		// Stopped projects nothing routes to are one node each; their services add nothing to the map.
		if len(stopped) > 0 {
			g.lines = append(g.lines, `  subgraph stopped["stopped"]`)
			for _, a := range stopped {
				id, _ := g.node("app|"+a.Name, diagnosis.Info)
				g.add("    ", id, rounded, a.Name, a.Kind+" · "+plural(len(a.Services), "service"), a.State)
			}
			g.lines = append(g.lines, "  end")
			g.styles = append(g.styles, "  style stopped fill:none,stroke:#8c959f,stroke-dasharray:4 3")
		}
	}
	if r != nil {
		g.styles = append(g.styles, "  style nginx fill:#ddf4ff,stroke:#0969da,color:#0a3069")
	}

	fmt.Fprintln(w, `%%{init: {"flowchart": {"curve": "basis"}}}%%`)
	fmt.Fprintln(w, "flowchart LR")
	for _, l := range g.lines {
		fmt.Fprintln(w, l)
	}
	for _, l := range g.edges {
		fmt.Fprintln(w, l)
	}
	for _, l := range g.classes {
		fmt.Fprintln(w, l)
	}
	for _, l := range g.styles {
		fmt.Fprintln(w, l)
	}
	fmt.Fprintln(w, "  classDef ok fill:#dafbe1,stroke:#2da44e,color:#0d3a1a")
	fmt.Fprintln(w, "  classDef bad fill:#ffebe9,stroke:#cf222e,stroke-width:2px,color:#82071e")
	fmt.Fprintln(w, "  classDef warn fill:#fff8c5,stroke:#bf8700,color:#4d2d00")
	fmt.Fprintln(w, "  classDef info fill:#f6f8fa,stroke:#8c959f,color:#57606a,stroke-dasharray:4 3")
}

// Mermaid prints the diagram as a fenced block, ready to paste into a README.
func Mermaid(w io.Writer, r *diagnosis.MapReport, inv *diagnosis.Inventory) {
	fmt.Fprintln(w, "```mermaid")
	mermaidCode(w, r, inv)
	fmt.Fprintln(w, "```")
}

// MermaidLink returns a mermaid.live URL that opens the diagram. The diagram is encoded in the
// URL fragment, which browsers never send to the server.
func MermaidLink(r *diagnosis.MapReport, inv *diagnosis.Inventory) string {
	var code strings.Builder
	mermaidCode(&code, r, inv)
	state, _ := json.Marshal(map[string]any{"code": code.String(), "mermaid": `{"theme":"default"}`, "updateDiagram": true})
	var buf bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	zw.Write(state)
	zw.Close()
	return "https://mermaid.live/edit#pako:" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func appGraph(g *graph, a *diagnosis.App, indent, nginxContainer string) {
	if a.Kind == "docker compose" {
		sg := safeID("compose_" + a.Name)
		g.lines = append(g.lines, fmt.Sprintf("%ssubgraph %s[\"%s\"]", indent, sg, esc(a.Name+" · docker compose")))
		for _, s := range a.Services {
			// nginx itself is already drawn as the nginx box.
			if nginxContainer != "" && s.Container != nil && s.Container.Name == nginxContainer {
				continue
			}
			image := ""
			if s.Container != nil {
				image = s.Container.Image
			}
			id, _ := g.node("svc|"+a.Name+"|"+s.Name, s.Status)
			g.add(indent+"  ", id, serviceShape(s.Name, image), s.Name+portsLine(s.Ports), s.State)
		}
		g.lines = append(g.lines, indent+"end")
		g.styles = append(g.styles, fmt.Sprintf("  style %s fill:none,stroke:#8c959f", sg))
		return
	}
	id, _ := g.node("app|"+a.Name, a.Status)
	details := []string{a.Kind}
	image := ""
	for _, f := range a.Facts {
		switch f.Label {
		case "folder":
			details = append(details, tildePath(f.Value))
		case "image":
			details = append(details, f.Value)
			image = f.Value
		}
	}
	details = append(details, a.State)
	g.add(indent, id, serviceShape(a.Name, image), a.Name+portsLine(a.Ports), details...)
}

var datastore = regexp.MustCompile(`(?i)(^|[^a-z])(postgres|postgresql|mysql|mariadb|redis|valkey|mongo|mongodb|memcached|elasticsearch|opensearch|clickhouse|db|database)([^a-z]|$)`)

// serviceShape draws databases and caches as cylinders.
func serviceShape(name, image string) shape {
	if datastore.MatchString(name) || datastore.MatchString(image) {
		return cylinder
	}
	return rounded
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
	return strings.NewReplacer(`"`, "#quot;", "<", "#lt;", ">", "#gt;").Replace(s)
}
