package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Project struct {
	File     string
	Services map[string]*Service
}

type Service struct {
	Name      string
	Ports     []Port
	Env       map[string]string
	DependsOn []string
}

type Port struct {
	Host      int
	Container int
}

var fileNames = []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"}

func Find(dir string) string {
	for {
		for _, n := range fileNames {
			p := filepath.Join(dir, n)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func Load(path string) (*Project, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.File = path
	return p, nil
}

type rawService struct {
	Ports       []any `yaml:"ports"`
	Environment any   `yaml:"environment"`
	DependsOn   any   `yaml:"depends_on"`
}

func Parse(b []byte) (*Project, error) {
	var raw struct {
		Services map[string]rawService `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	p := &Project{Services: map[string]*Service{}}
	for name, rs := range raw.Services {
		s := &Service{Name: name, Env: map[string]string{}}
		for _, port := range rs.Ports {
			if pt, ok := parsePort(port); ok {
				s.Ports = append(s.Ports, pt)
			}
		}
		switch env := rs.Environment.(type) {
		case []any:
			for _, e := range env {
				if k, v, ok := strings.Cut(fmt.Sprint(e), "="); ok {
					s.Env[k] = v
				}
			}
		case map[string]any:
			for k, v := range env {
				if v != nil {
					s.Env[k] = fmt.Sprint(v)
				}
			}
		}
		switch deps := rs.DependsOn.(type) {
		case []any:
			for _, d := range deps {
				s.DependsOn = append(s.DependsOn, fmt.Sprint(d))
			}
		case map[string]any:
			for d := range deps {
				s.DependsOn = append(s.DependsOn, d)
			}
		}
		sort.Strings(s.DependsOn)
		p.Services[name] = s
	}
	return p, nil
}

func parsePort(v any) (Port, bool) {
	switch v := v.(type) {
	case map[string]any:
		if proto, _ := v["protocol"].(string); proto != "" && proto != "tcp" {
			return Port{}, false
		}
		target, _ := strconv.Atoi(fmt.Sprint(v["target"]))
		host, _ := strconv.Atoi(fmt.Sprint(v["published"]))
		return Port{Host: host, Container: target}, target != 0
	case string, int:
		s := fmt.Sprint(v)
		s, proto, _ := strings.Cut(s, "/")
		if proto != "" && proto != "tcp" {
			return Port{}, false
		}
		parts := strings.Split(s, ":")
		if strings.Contains(s, "-") {
			return Port{}, false
		}
		target, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			return Port{}, false
		}
		pt := Port{Container: target}
		if len(parts) >= 2 {
			pt.Host, _ = strconv.Atoi(parts[len(parts)-2])
		}
		return pt, true
	}
	return Port{}, false
}

func (p *Project) ByHostPort(port int) *Service {
	for _, s := range p.sorted() {
		for _, pt := range s.Ports {
			if pt.Host == port {
				return s
			}
		}
	}
	return nil
}

func (p *Project) sorted() []*Service {
	var out []*Service
	for _, s := range p.Services {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
