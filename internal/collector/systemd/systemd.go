package systemd

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/runner"
)

type Unit struct {
	Name       string
	Active     string // active, failed, inactive, activating
	Sub        string // running, dead, auto-restart, ...
	Result     string // success, exit-code, signal, core-dump, oom-kill, ...
	ExitStatus int
	Restarts   int
	Since      string
	Started    time.Time
	File       string
	Exec       string
	Dir        string
	User       string
}

func (u *Unit) Down() bool { return u.Active != "active" || u.Sub == "auto-restart" }

func (u *Unit) StateText() string {
	s := u.Active
	if u.Sub != "" && u.Sub != u.Active {
		s += " (" + u.Sub + ")"
	}
	if u.Result != "" && u.Result != "success" {
		s += ", " + u.Result
		if u.Result == "exit-code" {
			s += " " + strconv.Itoa(u.ExitStatus)
		}
	}
	if u.Restarts > 0 {
		s += ", restarted " + strconv.Itoa(u.Restarts) + "×"
	}
	return s
}

type Systemd struct {
	Runner runner.Runner
	Dirs   []string
}

func New(r runner.Runner) *Systemd {
	if !r.Has("systemctl") {
		return nil
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil
	}
	return &Systemd{Runner: r, Dirs: []string{"/etc/systemd/system"}}
}

func (s *Systemd) ForPort(ctx context.Context, port int) []*Unit {
	if s == nil {
		return nil
	}
	re := regexp.MustCompile(`(^|[^0-9])` + strconv.Itoa(port) + `([^0-9]|$)`)
	var out []*Unit
	for _, dir := range s.Dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.service"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			text := string(b)
			for _, ef := range envFiles(text) {
				if eb, err := os.ReadFile(ef); err == nil {
					text += "\n" + string(eb)
				}
			}
			if !re.MatchString(stripComments(text)) {
				continue
			}
			if u := s.Status(ctx, filepath.Base(f)); u != nil {
				if u.File == "" {
					u.File = f
				}
				out = append(out, u)
			}
		}
	}
	return out
}

func (s *Systemd) Status(ctx context.Context, name string) *Unit {
	if s == nil {
		return nil
	}
	out, err := s.Runner.Run(ctx, "systemctl", "show", name, "--no-pager",
		"-p", props)
	if err != nil {
		return nil
	}
	return parseShow(name, out)
}

const props = "ActiveState,SubState,Result,ExecMainStatus,NRestarts,StateChangeTimestamp,LoadState,FragmentPath,ExecStart,WorkingDirectory,User,ActiveEnterTimestamp"

func parseShow(name, out string) *Unit {
	u := &Unit{Name: name}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			if v == "not-found" {
				return nil
			}
		case "ActiveState":
			u.Active = v
		case "SubState":
			u.Sub = v
		case "Result":
			u.Result = v
		case "ExecMainStatus":
			u.ExitStatus, _ = strconv.Atoi(v)
		case "NRestarts":
			u.Restarts, _ = strconv.Atoi(v)
		case "StateChangeTimestamp":
			u.Since = v
		case "ActiveEnterTimestamp":
			if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", v); err == nil {
				u.Started = t
			}
		case "FragmentPath":
			u.File = v
		case "ExecStart":
			u.Exec = argv(v)
		case "WorkingDirectory":
			u.Dir = v
		case "User":
			u.User = v
		}
	}
	return u
}

func (s *Systemd) Failed(ctx context.Context) []string {
	if s == nil {
		return nil
	}
	out, err := s.Runner.Run(ctx, "systemctl", "list-units", "--type=service", "--state=failed", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil
	}
	var names []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			names = append(names, f[0])
		}
	}
	return names
}

func (s *Systemd) Logs(ctx context.Context, unit string, n int) ([]string, error) {
	out, err := s.Runner.Run(ctx, "journalctl", "-u", unit, "-n", strconv.Itoa(n), "--no-pager", "-o", "cat")
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" && !strings.HasPrefix(l, "Hint:") && !strings.Contains(l, "No journal files were opened") {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// argv pulls the command line out of ExecStart={ path=... ; argv[]=/bin/x --flag ; ... }.
func argv(v string) string {
	_, rest, ok := strings.Cut(v, "argv[]=")
	if !ok {
		return strings.TrimSpace(v)
	}
	cmd, _, _ := strings.Cut(rest, " ;")
	return strings.TrimSpace(cmd)
}

func envFiles(unit string) []string {
	var out []string
	for _, l := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "EnvironmentFile="); ok {
			out = append(out, strings.TrimPrefix(strings.TrimSpace(v), "-"))
		}
	}
	return out
}

func stripComments(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}
