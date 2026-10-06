package render

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/diagnosis"
)

type shape struct{ open, close string }

var (
	box      = shape{"[", "]"}
	rounded  = shape{"[", "]"} // corners come from rx/ry in classDef
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

// add defines a node: product logo and bold title over smaller detail lines, with ✗ or ! when it
// needs attention.
func (g *graph) add(indent, id string, sh shape, logo, title string, details ...string) {
	switch g.status[id] {
	case diagnosis.Fail:
		title = "✗ " + title
	case diagnosis.Warn:
		title = "! " + title
	}
	label := "<b>" + esc(title) + "</b>"
	if logo != "" {
		label = fmt.Sprintf("<img src='https://cdn.simpleicons.org/%s' width='40' height='40' style='width:40px;height:40px;vertical-align:middle'/> %s", logo, label)
	}
	for _, d := range details {
		if d != "" {
			label += "<br/><small style='color:#64748b'>" + esc(d) + "</small>"
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
		g.styles = append(g.styles, fmt.Sprintf("  linkStyle %d stroke:#ef4444,stroke-width:2px", len(g.edges)))
	case diagnosis.Warn:
		// A warning on a database (say, a public port) doesn't make the apps that use it suspect.
		if !dotted {
			g.styles = append(g.styles, fmt.Sprintf("  linkStyle %d stroke:#f59e0b,stroke-width:2px", len(g.edges)))
		}
	}
	g.edges = append(g.edges, e)
}

// mermaidCode draws clients → nginx sites → apps (grouped by how they run) → what they connect to.
func mermaidCode(w io.Writer, r *diagnosis.MapReport, inv *diagnosis.Inventory) {
	g := &graph{ids: map[string]string{}, status: map[string]diagnosis.Status{}}
	used := map[*diagnosis.App]bool{}
	nginxContainer := ""
	if r != nil {
		nginxContainer = r.Config.Container
	}
	g.lines = append(g.lines, `  clients["<img src='https://api.iconify.design/lucide/monitor-smartphone.svg?color=%232563eb' width='40' height='40' style='width:40px;height:40px;vertical-align:middle'/> <b>clients</b><br/><small style='color:#64748b'>browsers · apps · APIs</small>"]`)

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
					sh, detail = hexagon, "external host"
					if !pr.Up() {
						detail += " · unreachable"
					}
				case !pr.Up():
					detail = "nothing listening"
				}
				g.add("  ", id, sh, "", pr.Addr(), detail)
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
		title := "nginx · reverse proxy"
		if nginxContainer != "" {
			title += " · container " + nginxContainer
		}
		g.lines = append(g.lines, fmt.Sprintf("  subgraph nginx[\"%s\"]", esc(title)))
		for _, s := range r.Servers {
			if s.Server.Ignored() {
				continue
			}
			st := diagnosis.Pass
			for _, step := range []*diagnosis.Step{s.Cert, s.TLS} {
				if step != nil && step.Status != diagnosis.Pass && st != diagnosis.Fail {
					st = step.Status
				}
			}
			tlsLine := ""
			if s.TLS != nil {
				tlsLine = s.TLS.Detail
			}
			id, _ := g.node("site|"+s.Server.Pos, st)
			g.add("    ", id, stadium, "nginx", s.Server.DisplayName(), "server · "+s.Server.ListenSummary()+published(r, s.Server), tlsLine)
		}
		g.lines = append(g.lines, "  end")
		for _, s := range r.Servers {
			if !s.Server.Ignored() {
				g.edge("clients", g.ids["site|"+s.Server.Pos], "", false)
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
						g.add("  ", tid, sh, "", label, detail)
					}
					g.edge(sid, tid, path, false)
					continue
				}
				for _, pr := range e.Probes {
					tid := target(pr)
					g.edge(sid, tid, path, false)
					// The probe knows whether localhost answered inside the container; draw it first so
					// the inventory link below reuses this node.
					for _, d := range pr.Deps {
						if d.Probe != nil && network.IsLocal(d.Name) && pr.Container != nil {
							st, detail := diagnosis.Warn, "inside the "+pr.Container.DisplayName()+" container"
							if !d.Probe.TCP.OK() {
								st, detail = diagnosis.Fail, detail+" · nothing listening"
							}
							if id, isNew := g.node("local|"+pr.Container.Name+"|"+d.Probe.Addr(), st); isNew {
								g.add("  ", id, box, "", d.Probe.Addr(), detail)
							}
						}
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
			g.styles = append(g.styles, "  style unrouted fill:none,stroke:#cbd5e1,stroke-dasharray:6 4,rx:14,ry:14")
		}
		// Stopped projects nothing routes to are one node each; their services add nothing to the map.
		if len(stopped) > 0 {
			g.lines = append(g.lines, `  subgraph stopped["stopped"]`)
			for _, a := range stopped {
				id, _ := g.node("app|"+a.Name, diagnosis.Info)
				g.add("    ", id, rounded, "docker", a.Name, "compose project · "+plural(len(a.Services), "service"), a.State)
			}
			g.lines = append(g.lines, "  end")
			g.styles = append(g.styles, "  style stopped fill:none,stroke:#cbd5e1,stroke-dasharray:6 4,rx:14,ry:14")
		}
		for _, a := range inv.Apps {
			if !a.Stopped {
				appEdges(g, a, nginxContainer)
			}
		}
	}
	if len(g.edges) == 0 || !strings.Contains(strings.Join(g.edges, "\n"), "clients ") {
		g.lines = g.lines[1:] // nothing is reachable from outside
	}
	if r != nil {
		g.styles = append(g.styles, "  style nginx fill:#eff6ff,stroke:#bfdbfe,color:#1e40af,rx:14,ry:14")
	}
	if len(g.lines) > 0 && strings.HasPrefix(g.lines[0], "  clients[") {
		g.styles = append(g.styles, "  style clients fill:#eff6ff,stroke:#3b82f6,stroke-width:1.5px,color:#1e3a8a,rx:16,ry:16")
	}

	fmt.Fprintln(w, theme)
	fmt.Fprintln(w, "flowchart LR")
	// Mermaid draws on a transparent background; a borderless outer group gives the diagram its own
	// white canvas on dark pages (mermaid.live in dark mode, GitHub dark theme).
	fmt.Fprintln(w, `  subgraph canvas[" "]`)
	fmt.Fprintln(w, "    direction LR")
	for _, l := range g.lines {
		fmt.Fprintln(w, "  "+l)
	}
	fmt.Fprintln(w, "  end")
	for _, l := range g.edges {
		fmt.Fprintln(w, l)
	}
	for _, l := range g.classes {
		fmt.Fprintln(w, l)
	}
	for _, l := range g.styles {
		fmt.Fprintln(w, l)
	}
	fmt.Fprintln(w, "  style canvas fill:#ffffff,stroke:#e2e8f0,rx:16,ry:16")
	fmt.Fprintln(w, "  classDef ok fill:#ffffff,stroke:#86efac,stroke-width:1.5px,color:#0f172a,rx:12,ry:12")
	fmt.Fprintln(w, "  classDef bad fill:#fef2f2,stroke:#ef4444,stroke-width:2px,color:#991b1b,rx:12,ry:12")
	fmt.Fprintln(w, "  classDef warn fill:#fffbeb,stroke:#f59e0b,stroke-width:1.5px,color:#92400e,rx:12,ry:12")
	fmt.Fprintln(w, "  classDef info fill:#f8fafc,stroke:#cbd5e1,stroke-dasharray:4 3,color:#64748b,rx:12,ry:12")
}

// theme is a light, card-like look: white nodes with soft borders and rounded corners, status in
// the border color, details in a muted gray.
const theme = `%%{init: {"theme": "base", "fontFamily": "Inter, ui-sans-serif, -apple-system, Segoe UI, Roboto, sans-serif", "themeVariables": {` +
	`"fontFamily": "Inter, ui-sans-serif, -apple-system, Segoe UI, Roboto, sans-serif", "fontSize": "13px", ` +
	`"background": "#ffffff", "primaryColor": "#ffffff", "primaryTextColor": "#0f172a", "primaryBorderColor": "#e2e8f0", ` +
	`"lineColor": "#94a3b8", "clusterBkg": "#f8fafc", "clusterBorder": "#e2e8f0", "titleColor": "#475569", ` +
	`"edgeLabelBackground": "#ffffff", "tertiaryTextColor": "#334155"}, ` +
	`"flowchart": {"curve": "basis", "padding": 14, "nodeSpacing": 40, "rankSpacing": 70}}}%%`

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
	state, _ := json.Marshal(map[string]any{"code": code.String(), "mermaid": `{"theme":"base"}`, "updateDiagram": true})
	var buf bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	zw.Write(state)
	zw.Close()
	return "https://mermaid.live/edit#pako:" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func appGraph(g *graph, a *diagnosis.App, indent, nginxContainer string) {
	if a.Kind == "docker compose" {
		sg := safeID("compose_" + a.Name)
		g.lines = append(g.lines, fmt.Sprintf("%ssubgraph %s[\"%s\"]", indent, sg, esc(a.Name+" · compose project")))
		for _, s := range a.Services {
			// nginx itself is already drawn as the nginx box.
			if isNginx(s, nginxContainer) {
				continue
			}
			id, _ := g.node("svc|"+a.Name+"|"+s.Name, s.Status)
			image := ""
			var details []string
			if c := s.Container; c != nil {
				image = c.Image
				details = append(details, "image "+shortImage(c.Image), containerPorts(s))
			}
			state := s.State
			if s.Container != nil && s.Container.Health != "" && s.Container.Running() && s.Status == diagnosis.Pass {
				state += " · " + s.Container.Health
			}
			details = append(details, state)
			if s.Usage != nil {
				details = append(details, s.Usage.String())
			}
			g.add(indent+"  ", id, serviceShape(s.Name, image), orLogo(logo(s.Name, image), "docker"), s.Name, details...)
		}
		g.lines = append(g.lines, indent+"end")
		g.styles = append(g.styles, fmt.Sprintf("  style %s fill:#f8fafc,stroke:#e2e8f0,rx:14,ry:14", sg))
		return
	}
	id, _ := g.node("app|"+a.Name, a.Status)
	details := []string{a.Kind}
	image, program := "", ""
	for _, f := range a.Facts {
		switch f.Label {
		case "folder":
			details = append(details, tildePath(f.Value))
		case "image":
			details = append(details, "image "+shortImage(f.Value))
			image = f.Value
		case "program", "command":
			if program == "" {
				program = f.Value
			}
		}
	}
	if p := portsLine(a.Ports); p != "" {
		details = append(details, "port"+p)
	}
	details = append(details, a.State)
	if a.Usage != nil {
		details = append(details, a.Usage.String())
	}
	key := image
	if key == "" {
		key = program
	}
	fallback := "linux"
	if a.Kind == "docker container" {
		fallback = "docker"
	}
	g.add(indent, id, serviceShape(a.Name, key), orLogo(logo(a.Name, key), fallback), a.Name, details...)
}

// appEdges draws how clients reach an app (published ports) and what the app connects to.
func appEdges(g *graph, a *diagnosis.App, nginxContainer string) {
	if a.Kind != "docker compose" {
		id := g.ids["app|"+a.Name]
		for _, p := range a.Ports {
			if p.Port != 0 && !p.Down {
				g.edge("clients", id, portLabel(p), false)
			}
		}
		return
	}
	for _, s := range a.Services {
		if isNginx(s, nginxContainer) || s.Container == nil {
			continue
		}
		id := g.ids["svc|"+a.Name+"|"+s.Name]
		for _, p := range s.Ports {
			if p.Port != 0 {
				g.edge("clients", id, portLabel(p), false)
			}
		}
		for _, l := range s.Links {
			if l.Addr != "" {
				tid, isNew := g.node("local|"+s.Container.Name+"|"+l.Addr, diagnosis.Warn)
				if isNew {
					g.add("  ", tid, box, "", l.Addr, "inside the "+s.Name+" container")
				}
				g.edge(id, tid, l.Via, true)
				continue
			}
			if tid, ok := g.ids["svc|"+a.Name+"|"+l.Service]; ok {
				g.edge(id, tid, l.Via, true)
			}
		}
	}
}

// portLabel marks ports other machines can reach.
func portLabel(p diagnosis.AppPort) string {
	if p.Local {
		return fmt.Sprintf(":%d · local", p.Port)
	}
	return fmt.Sprintf(":%d · public", p.Port)
}

func isPublic(ports []diagnosis.AppPort) bool {
	for _, p := range ports {
		if p.Port != 0 && !p.Local {
			return true
		}
	}
	return false
}

func isNginx(s *diagnosis.AppService, nginxContainer string) bool {
	return nginxContainer != "" && s.Container != nil && s.Container.Name == nginxContainer
}

// containerPorts reads like docker ps: published host→container ports, else the exposed ones.
func containerPorts(s *diagnosis.AppService) string {
	c := s.Container
	var out []string
	for _, b := range c.Bindings {
		// IPv4 and IPv6 bindings of the same port read as one.
		if p := fmt.Sprintf("%d→%d", b.HostPort, b.ContainerPort); !contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) > 0 {
		scope := "localhost only"
		if isPublic(s.Ports) {
			scope = "public, all interfaces"
		}
		return "ports " + strings.Join(out, " ") + " · " + scope
	}
	for _, p := range c.Exposed {
		out = append(out, fmt.Sprint(p))
	}
	if len(out) > 0 {
		return "expose " + strings.Join(out, " ")
	}
	return ""
}

// shortImage drops the registry and digest: docker.io/library/postgres:16@sha256:… → postgres:16.
func shortImage(img string) string {
	img, _, _ = strings.Cut(img, "@")
	for _, p := range []string{"docker.io/library/", "docker.io/", "library/"} {
		img = strings.TrimPrefix(img, p)
	}
	return img
}

// serviceShape draws databases and caches as cylinders.
func serviceShape(name, image string) shape {
	if diagnosis.IsDatastore(name, image) {
		return cylinder
	}
	return rounded
}

// logos maps what an app runs (image, program or name) to its Simple Icons slug; first match wins.
var logos = []struct{ match, slug string }{
	{"nginx", "nginx"}, {"postgres", "postgresql"}, {"mysql", "mysql"}, {"mariadb", "mariadb"},
	{"redis", "redis"}, {"valkey", "redis"}, {"mongo", "mongodb"}, {"rabbitmq", "rabbitmq"},
	{"kafka", "apachekafka"}, {"elasticsearch", "elasticsearch"}, {"opensearch", "opensearch"},
	{"clickhouse", "clickhouse"}, {"grafana", "grafana"}, {"prometheus", "prometheus"},
	{"traefik", "traefikproxy"}, {"caddy", "caddy"}, {"minio", "minio"}, {"httpd", "apache"},
	{"node", "nodedotjs"}, {"bun", "bun"}, {"deno", "deno"}, {"python", "python"}, {"gunicorn", "gunicorn"},
	{"uvicorn", "python"}, {"php", "php"}, {"ruby", "ruby"}, {"java", "openjdk"}, {"openjdk", "openjdk"},
	{"golang", "go"}, {"dotnet", "dotnet"},
}

func logo(name, runs string) string {
	for _, s := range []string{runs, name} {
		s = strings.ToLower(s)
		for _, l := range logos {
			if strings.Contains(s, l.match) {
				return l.slug
			}
		}
	}
	return ""
}

func orLogo(slug, fallback string) string {
	if slug == "" {
		return fallback
	}
	return slug
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
