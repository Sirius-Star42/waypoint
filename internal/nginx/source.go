package nginx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/runner"
)

type osFS struct{}

func (osFS) ReadFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

func (osFS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

type dumpFS map[string]string

func (d dumpFS) ReadFile(path string) (string, error) {
	if s, ok := d[path]; ok {
		return s, nil
	}
	return "", fmt.Errorf("%s: not in nginx -T output", path)
}

func (d dumpFS) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range d {
		if ok, _ := filepath.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

var dumpHeader = regexp.MustCompile(`(?m)^# configuration file (.+):\r?$`)

func splitDump(out string) (dumpFS, string) {
	idx := dumpHeader.FindAllStringSubmatchIndex(out, -1)
	files := dumpFS{}
	main := ""
	for i, m := range idx {
		name := out[m[2]:m[3]]
		end := len(out)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		body := out[m[1]:end]
		body = strings.TrimPrefix(strings.TrimPrefix(body, "\r"), "\n")
		files[name] = body
		if i == 0 {
			main = name
		}
	}
	return files, main
}

var defaultPaths = []string{
	"/etc/nginx/nginx.conf",
	"/usr/local/etc/nginx/nginx.conf",
	"/opt/homebrew/etc/nginx/nginx.conf",
	"/usr/local/nginx/conf/nginx.conf",
}

func Load(ctx context.Context, r runner.Runner, path string) (*Config, error) {
	if path != "" {
		return fromFS(osFS{}, path, "file "+path)
	}
	var notes []string
	if r.Has("nginx") {
		out, err := r.Run(ctx, "nginx", "-T")
		if err == nil {
			if files, main := splitDump(out); main != "" {
				cfg, err := fromFS(files, main, "nginx -T")
				if err == nil {
					return cfg, nil
				}
				notes = append(notes, "could not parse nginx -T output: "+err.Error())
			}
		}
		testErr := EmergError(errText(err))
		if err != nil && testErr == "" {
			notes = append(notes, "nginx -T failed ("+firstLine(err.Error())+"), reading config files directly; run with sudo for the exact running config")
		}
		if p := confPathFromVersion(ctx, r); p != "" {
			if cfg, err := fromFS(osFS{}, p, "file "+p); err == nil {
				cfg.Notes = append(notes, cfg.Notes...)
				cfg.TestError = testErr
				return cfg, nil
			}
		}
		for _, p := range defaultPaths {
			if _, err := os.Stat(p); err == nil {
				cfg, err := fromFS(osFS{}, p, "file "+p)
				if err != nil {
					return nil, err
				}
				cfg.Notes = append(notes, cfg.Notes...)
				cfg.TestError = testErr
				return cfg, nil
			}
		}
	}
	for _, p := range defaultPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		cfg, err := fromFS(osFS{}, p, "file "+p)
		if err != nil {
			return nil, err
		}
		cfg.Notes = append(notes, cfg.Notes...)
		return cfg, nil
	}
	if cfg := fromContainer(ctx, r); cfg != nil {
		return cfg, nil
	}
	return nil, nil
}

func fromContainer(ctx context.Context, r runner.Runner) *Config {
	if !r.Has("docker") {
		return nil
	}
	out, err := r.Run(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Image}}")
	if err != nil {
		return nil
	}
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		name, image, ok := strings.Cut(l, "\t")
		if ok && strings.Contains(image, "nginx") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		dump, err := r.Run(ctx, "docker", "exec", name, "nginx", "-T")
		var cfg *Config
		if err == nil {
			if files, main := splitDump(dump); main != "" {
				cfg, _ = fromFS(files, main, "docker exec "+name+" nginx -T")
			}
		}
		if cfg == nil {
			// nginx -T refuses to print a config that fails its test; read the files instead.
			cfs := containerFS{ctx: ctx, r: r, name: name}
			cfg, _ = fromFS(cfs, "/etc/nginx/nginx.conf", "files in container "+name)
			if cfg == nil {
				continue
			}
			cfg.TestError = EmergError(errText(err))
		}
		cfg.Container = name
		return cfg
	}
	return nil
}

type containerFS struct {
	ctx  context.Context
	r    runner.Runner
	name string
}

func (c containerFS) ReadFile(path string) (string, error) {
	return c.r.Run(c.ctx, "docker", "exec", c.name, "cat", path)
}

func (c containerFS) Glob(pattern string) ([]string, error) {
	out, err := c.r.Run(c.ctx, "docker", "exec", c.name, "sh", "-c", "for f in "+pattern+"; do [ -e \"$f\" ] && echo \"$f\"; done; true")
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

func EmergError(out string) string {
	for _, l := range strings.Split(out, "\n") {
		_, msg, ok := strings.Cut(l, "[emerg] ")
		if !ok {
			continue
		}
		if strings.Contains(msg, "Permission denied") {
			return ""
		}
		if i := strings.Index(msg, ": "); i >= 0 && strings.Contains(msg[:i], "#") {
			msg = msg[i+2:]
		}
		return strings.TrimSpace(msg)
	}
	return ""
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func confPathFromVersion(ctx context.Context, r runner.Runner) string {
	out, _ := r.Run(ctx, "nginx", "-V")
	for _, f := range strings.Fields(out) {
		if v, ok := strings.CutPrefix(f, "--conf-path="); ok {
			return v
		}
	}
	return ""
}

func fromFS(fs FS, path, source string) (*Config, error) {
	dirs, files, warnings, err := Parse(fs, path)
	if err != nil {
		return nil, err
	}
	cfg := Build(dirs)
	cfg.Source = source
	cfg.Main = path
	cfg.Files = files
	cfg.Notes = append(warnings, cfg.Notes...)
	return cfg, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
