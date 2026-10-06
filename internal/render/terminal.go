package render

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/Sirius-Star42/waypoint/internal/collector/network"
	"github.com/Sirius-Star42/waypoint/internal/diagnosis"
	"github.com/Sirius-Star42/waypoint/internal/nginx"
)

type Printer struct {
	W       io.Writer
	Color   bool
	Verbose bool
}

func New(w io.Writer, verbose bool) *Printer {
	return &Printer{W: w, Color: colorEnabled(w), Verbose: verbose}
}

func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

const (
	red    = "31"
	green  = "32"
	yellow = "33"
	dim    = "2"
	bold   = "1"
)

func (p *Printer) c(code, s string) string {
	if !p.Color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p *Printer) f(format string, a ...any) { fmt.Fprintf(p.W, format, a...) }

func (p *Printer) icon(s diagnosis.Status) string {
	switch s {
	case diagnosis.Pass:
		return p.c(green, "✓")
	case diagnosis.Fail:
		return p.c(red, "✗")
	case diagnosis.Warn:
		return p.c(yellow, "!")
	}
	return p.c(dim, "·")
}

func pad(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// Overview prints the sites nginx serves, the apps running on this machine and the problems found.
func (p *Printer) Overview(r *diagnosis.MapReport, inv *diagnosis.Inventory, issues []*diagnosis.Finding) {
	if r != nil {
		p.sites(r, inv)
	}
	if inv != nil {
		p.apps(inv, r != nil)
	}
	p.problems(issues, r != nil, inv)
}

func (p *Printer) section(title, sub string) {
	p.f("%s  %s\n", p.c(bold, title), p.c(dim, sub))
}

func (p *Printer) sites(r *diagnosis.MapReport, inv *diagnosis.Inventory) {
	cfg := r.Config
	src := cfg.Source
	if cfg.Container != "" {
		src = "nginx in container " + cfg.Container
	}
	p.section("SITES", fmt.Sprintf("served by nginx · %s · %d config files", src, len(cfg.Files)))
	if len(r.Down) > 0 {
		var ports []string
		for _, port := range r.Down {
			ports = append(ports, fmt.Sprintf(":%d", port))
		}
		p.f("%s %s\n", p.icon(diagnosis.Fail), p.c(red, "nginx is not answering on "+strings.Join(ports, " ")))
	}
	for _, s := range r.Servers {
		if s.Server.Ignored() {
			p.f("\n%s  %s  %s\n", p.c(dim, s.Server.DisplayName()), p.c(dim, s.Server.ListenSummary()), p.c(yellow, "ignored: name already used by an earlier server block"))
			continue
		}
		p.f("\n%s  %s", p.c(bold, s.Server.DisplayName()), p.c(dim, s.Server.ListenSummary()+published(r, s.Server)))
		if extra := extraNames(s.Server); extra != "" {
			p.f(" %s", p.c(dim, "+ "+extra))
		}
		if s.Cert != nil {
			p.f("  %s %s", p.icon(s.Cert.Status), p.detail(s.Cert.Status, "certificate: "+s.Cert.Detail))
		}
		p.f("\n")
		locW, tgtW := 0, 0
		for _, e := range s.Entries {
			locW = max(locW, utf8.RuneCountInString(locText(e))+e.Nested*2)
			tgtW = max(tgtW, utf8.RuneCountInString(e.Target))
		}
		tgtW = min(tgtW, 44)
		for i, e := range s.Entries {
			branch, cont := "├─ ", "│  "
			if i == len(s.Entries)-1 {
				branch, cont = "└─ ", "   "
			}
			loc := pad(strings.Repeat("  ", e.Nested)+locText(e), locW)
			detail := e.Detail
			if len(e.Probes) == 1 {
				detail = appDetail(inv, e.Probes[0], e.Status, detail)
			}
			line := fmt.Sprintf("%s%s  → %s  %s %s", p.c(dim, branch), loc, pad(e.Target, tgtW), p.icon(e.Status), p.detail(e.Status, detail))
			p.f("%s\n", strings.TrimRight(line, " "))
			subs := e.Sub
			for j, sub := range subs {
				sb := "└─ "
				if j < len(subs)-1 {
					sb = "├─ "
				}
				d := sub.Detail
				if len(e.Probes) > 1 && j < len(e.Probes) {
					d = appDetail(inv, e.Probes[j], sub.Status, d)
				}
				p.f("%s%s%s%s %s %s\n", p.c(dim, cont), strings.Repeat(" ", locW+5), p.c(dim, sb), sub.Text, p.icon(sub.Status), p.detail(sub.Status, d))
			}
		}
	}
	p.f("\n")
}

// appDetail names the app behind an upstream ("my-api · systemd") instead of a pid.
func appDetail(inv *diagnosis.Inventory, pr *diagnosis.Probe, st diagnosis.Status, fallback string) string {
	a, svc := inv.AppOf(pr)
	if a == nil {
		if pr.Unix == "" && pr.Via == nil && !network.IsLocal(pr.Host) {
			return joinNonEmpty("another machine", fallback)
		}
		return fallback
	}
	name := a.Name
	kind := shortKind(a.Kind)
	if svc != nil && a.Kind == "docker compose" {
		name = svc.Name
		kind = "compose " + a.Name
	}
	s := name + " · " + kind
	if st != diagnosis.Pass {
		s = fallback
		if !strings.Contains(fallback, name) {
			s = name + " · " + fallback
		}
	}
	return s
}

func shortKind(k string) string {
	switch k {
	case "systemd service":
		return "systemd"
	case "docker container":
		return "docker"
	}
	return k
}

func (p *Printer) apps(inv *diagnosis.Inventory, haveNginx bool) {
	var active, stopped []*diagnosis.App
	down := 0
	for _, a := range inv.Apps {
		if a.Stopped {
			stopped = append(stopped, a)
			continue
		}
		active = append(active, a)
		if a.Status == diagnosis.Fail {
			down++
		}
	}
	sub := "nothing running"
	if len(active) > 0 {
		sub = plural(len(active), "app") + " on this machine"
	}
	if down > 0 {
		sub += fmt.Sprintf(" · %d with problems", down)
	}
	if len(stopped) > 0 {
		sub += " · " + plural(len(stopped), "stopped compose project")
	}
	if len(inv.Stopped) > 0 {
		sub += " · " + plural(len(inv.Stopped), "old container")
	}
	p.section("APPS", sub)
	nameW := 0
	for _, a := range active {
		nameW = max(nameW, utf8.RuneCountInString(a.Name))
	}
	nameW = min(max(nameW, 12), 28)
	for _, a := range active {
		p.f("\n%s %s  %s\n", p.icon(a.Status), p.c(bold, pad(a.Name, nameW)), p.detail(stateStatus(a.Status), a.Kind+" · "+a.State))
		for _, f := range a.Facts {
			switch f.Label {
			case "manage":
			case "folder", "file", "unit file":
				p.fact(f.Label, truncate(tildePath(f.Value), 110))
			default:
				p.fact(f.Label, truncate(f.Value, 110))
			}
		}
		p.ports(a.Ports)
		p.services(a.Services)
		for _, f := range a.Facts {
			if f.Label == "manage" {
				p.fact("manage", p.c(green, tildeCmd(f.Value)))
			}
		}
		for _, n := range a.Notes {
			p.f("    %s %s\n", p.icon(diagnosis.Warn), p.c(yellow, n))
		}
	}
	if len(stopped) > 0 {
		rows := [][]string{{"NAME", "STOPPED", "COMPOSE FILE"}}
		for _, a := range stopped {
			file := ""
			for _, f := range a.Facts {
				if f.Label == "file" {
					file = tildePath(f.Value)
				}
			}
			rows = append(rows, []string{a.Name, orUnknown(diagnosis.Ago(a.StoppedAt)), file})
		}
		p.table("STOPPED PROJECTS", rows)
	}
	if len(inv.Stopped) > 0 {
		rows := [][]string{{"NAME", "STATE", "STOPPED"}}
		for _, c := range inv.Stopped {
			rows = append(rows, []string{c.Name, c.State, orUnknown(diagnosis.Ago(c.At))})
		}
		p.table("OLD CONTAINERS", rows)
	}
	if len(inv.Elsewhere) > 0 {
		p.f("\n%s\n", p.c(bold, "On other machines"))
		for _, r := range inv.Elsewhere {
			p.f("  %s  %s\n", r.Addr, p.c(dim, "← "+strings.Join(r.Routes, ", ")))
		}
	}
	if len(inv.Unknown) > 0 || len(inv.System) > 0 {
		p.f("\n")
	}
	if len(inv.Unknown) > 0 {
		var ports []string
		for _, port := range inv.Unknown {
			ports = append(ports, fmt.Sprintf(":%d", port))
		}
		p.fact("hidden", strings.Join(ports, " ")+p.c(dim, "  owned by other users; run with sudo to see them"))
	}
	if len(inv.System) > 0 && p.Verbose {
		for i, sys := range inv.System {
			label := ""
			if i == 0 {
				label = "system"
			}
			p.fact(label, p.c(dim, sys))
		}
	} else if n := len(inv.System); n > 0 {
		msg := "1 system process hidden (-v to show)"
		if n > 1 {
			msg = fmt.Sprintf("%d system processes hidden (-v to show)", n)
		}
		p.f("  %s %s\n", p.icon(diagnosis.Info), p.c(dim, msg))
	}
	p.f("\n")
}

// table prints rows as aligned columns under a title; the first row is the header.
func (p *Printer) table(title string, rows [][]string) {
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, cell := range r {
			widths[i] = max(widths[i], utf8.RuneCountInString(cell))
		}
	}
	p.f("\n%s\n", p.c(bold, title))
	for n, r := range rows {
		var cells []string
		for i, cell := range r {
			if i < len(r)-1 {
				cell = pad(cell, widths[i])
			}
			cells = append(cells, cell)
		}
		line := strings.TrimRight(strings.Join(cells, "   "), " ")
		if n == 0 {
			line = p.c(dim, line)
		}
		p.f("  %s\n", line)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// tildeCmd shortens home paths inside a command; the shell expands ~ back.
func tildeCmd(cmd string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/" {
		return cmd
	}
	return strings.ReplaceAll(cmd, " "+home+"/", " ~/")
}

// tildePath shortens paths under the user's home directory to ~/...
func tildePath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/" {
		return path
	}
	if path == home {
		return "~"
	}
	if rest, ok := strings.CutPrefix(path, home+"/"); ok {
		return "~/" + rest
	}
	return path
}

func (p *Printer) fact(label, value string) {
	p.f("    %s %s\n", p.c(dim, pad(label, 9)), value)
}

// ports prints routed ports one per line and folds the rest into one line.
func (p *Printer) ports(ports []diagnosis.AppPort) {
	var plain []string
	allLocal := true
	for _, port := range ports {
		if len(port.Routes) > 0 {
			p.fact("port", p.portText(port, true))
			continue
		}
		plain = append(plain, fmt.Sprintf(":%d", port.Port))
		allLocal = allLocal && port.Local
	}
	if len(plain) == 0 {
		return
	}
	where := " all interfaces"
	if allLocal {
		where = " local only"
	}
	label := "port"
	if len(plain) > 1 {
		label = "ports"
	}
	p.fact(label, strings.Join(plain, " ")+p.c(dim, where))
}

func (p *Printer) services(svcs []*diagnosis.AppService) {
	w := 0
	for _, s := range svcs {
		w = max(w, utf8.RuneCountInString(s.Name))
	}
	for _, s := range svcs {
		var ports []string
		var routes []string
		for _, port := range s.Ports {
			if port.Port != 0 {
				ports = append(ports, fmt.Sprintf(":%d", port.Port))
			}
			routes = append(routes, port.Routes...)
		}
		line := fmt.Sprintf("    %s %s  %s  %s", p.icon(s.Status), pad(s.Name, w), pad(strings.Join(ports, " "), 6), p.detail(stateStatus(s.Status), s.State))
		if len(routes) > 0 {
			line += "  " + p.c(dim, "← ") + strings.Join(dedupe(routes), ", ")
		}
		p.f("%s\n", line)
	}
}

func (p *Printer) portText(port diagnosis.AppPort, haveNginx bool) string {
	s := fmt.Sprintf(":%d", port.Port)
	if port.Down {
		s += p.c(red, " not listening")
	} else if port.Local {
		s += p.c(dim, " local only")
	} else {
		s += p.c(dim, " all interfaces")
	}
	if len(port.Routes) > 0 {
		s += "  " + p.c(dim, "← ") + strings.Join(port.Routes, ", ")
	}
	return s
}

func stateStatus(s diagnosis.Status) diagnosis.Status {
	if s == diagnosis.Pass {
		return diagnosis.Info
	}
	return s
}

func (p *Printer) problems(fs []*diagnosis.Finding, haveNginx bool, inv *diagnosis.Inventory) {
	if len(fs) == 0 {
		msg := "everything checks out"
		if haveNginx {
			msg = "every route and app checks out"
		} else if inv != nil && !inv.Running() {
			msg = "no problems · nothing is running"
		}
		p.f("%s %s\n", p.icon(diagnosis.Pass), p.c(green, msg))
		return
	}
	p.section("PROBLEMS", plural(len(fs), "problem")+", most important first")
	for i, f := range fs {
		st := diagnosis.Fail
		if f.Confidence < 0.6 {
			st = diagnosis.Warn
		}
		p.f("\n%s %s\n", p.icon(st), p.c(bold, f.Title))
		if i == 0 || p.Verbose {
			p.findingBody(f, "  ")
			continue
		}
		for _, fix := range f.Fixes {
			if fix.Command != "" {
				p.f("  %s\n", p.c(green, "$ "+fix.Command))
				break
			}
		}
	}
	p.f("\n%s\n", p.c(dim, "waypoint <url or port> traces one request · -v shows evidence and logs for every problem"))
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return fmt.Sprintf("%d %ss", n, w)
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
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

func (p *Printer) detail(s diagnosis.Status, d string) string {
	switch s {
	case diagnosis.Fail:
		return p.c(red, d)
	case diagnosis.Warn:
		return p.c(yellow, d)
	}
	return p.c(dim, d)
}

func locText(e *diagnosis.MapEntry) string {
	if e.Location == nil {
		return "return"
	}
	return e.Location.String()
}

func extraNames(s *nginx.Server) string {
	var names []string
	first := s.DisplayName()
	for _, n := range s.Names {
		if n != first && n != "" && n != "_" {
			names = append(names, n)
		}
	}
	if len(names) > 3 {
		names = append(names[:3], fmt.Sprintf("%d more", len(names)-3))
	}
	return strings.Join(names, " ")
}

func (p *Printer) Diagnose(r *diagnosis.Report) {
	if r.OK() {
		p.f("%s %s\n", p.icon(diagnosis.Pass), p.c(bold, r.Summary))
	} else {
		p.f("%s %s\n", p.icon(diagnosis.Fail), p.c(bold, r.Root.Title))
	}
	if len(r.Steps) > 0 {
		p.f("\n")
		w := 0
		for _, s := range r.Steps {
			w = max(w, utf8.RuneCountInString(s.Text)+s.Indent*2)
		}
		w = min(w, 56)
		for _, s := range r.Steps {
			text := pad(strings.Repeat("  ", s.Indent)+s.Text, w)
			line := fmt.Sprintf("  %s %s  %s", p.icon(s.Status), text, p.detail(s.Status, s.Detail))
			if s.Pos != "" && s.Detail == "" {
				line += p.c(dim, s.Pos)
			} else if s.Pos != "" {
				line += "  " + p.c(dim, s.Pos)
			}
			p.f("%s\n", strings.TrimRight(line, " "))
		}
	}
	if r.Root != nil {
		p.f("\n")
		p.findingBody(r.Root, "  ")
	}
	if len(r.Others) > 0 {
		p.f("\n  %s\n", p.c(bold, "Also"))
		for _, f := range r.Others {
			p.f("    %s %s\n", p.icon(diagnosis.Warn), f.Title)
			// Without a root cause the reader has nothing else to act on, so show how to follow up.
			if r.Root == nil {
				for _, fix := range f.Fixes {
					if fix.Command != "" {
						p.f("      %s\n", p.c(green, "$ "+fix.Command))
						break
					}
				}
			}
		}
	}
}

func (p *Printer) findingBody(f *diagnosis.Finding, in string) {
	if f.Detail != "" {
		p.f("%s%s\n", in, f.Detail)
	}
	if len(f.Evidence) > 0 {
		p.f("\n%s%s\n", in, p.c(bold, "Evidence"))
		for _, e := range f.Evidence {
			p.f("%s  %s %s\n", in, p.icon(e.Status), e.Text)
		}
	}
	if len(f.Logs) > 0 {
		p.f("\n%s%s %s\n", in, p.c(bold, "Last logs"), p.c(dim, f.LogSource))
		logs := collapse(f.Logs)
		if !p.Verbose && len(logs) > 6 {
			logs = logs[len(logs)-6:]
		}
		for _, l := range logs {
			if len(l) > 200 {
				l = l[:197] + "..."
			}
			p.f("%s  %s %s\n", in, p.c(dim, "│"), l)
		}
	}
	if len(f.Fixes) > 0 {
		p.f("\n%s%s\n", in, p.c(bold, "Fix"))
		for _, fix := range f.Fixes {
			p.f("%s  %s\n", in, fix.Text)
			if fix.Command != "" {
				p.f("%s    %s\n", in, p.c(green, "$ "+tildeCmd(fix.Command)))
			}
		}
	}
}

func (p *Printer) Notes(notes []string) {
	for _, n := range notes {
		p.f("%s\n", p.c(dim, "note: "+n))
	}
}

func collapse(lines []string) []string {
	var out []string
	n := 0
	for i, l := range lines {
		n++
		if i+1 < len(lines) && lines[i+1] == l {
			continue
		}
		if n > 1 {
			l = fmt.Sprintf("%s  (×%d)", l, n)
		}
		out = append(out, l)
		n = 0
	}
	return out
}

func published(r *diagnosis.MapReport, s *nginx.Server) string {
	var out []string
	for _, l := range s.Listens {
		if hp, ok := r.Published[l.Port]; ok && hp != l.Port {
			out = append(out, fmt.Sprintf(":%d", hp))
		}
	}
	if len(out) == 0 {
		return ""
	}
	return " (host " + strings.Join(out, " ") + ")"
}

func joinNonEmpty(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " · ")
}
