package nginx

import (
	"fmt"
	"strconv"
	"strings"
)

type Config struct {
	Source    string // how it was read: "nginx -T", "file /etc/nginx/nginx.conf", ...
	Main      string
	Files     []string
	Container string // set when the config was read from an nginx container
	Servers   []*Server
	Upstreams map[string][]Endpoint
	Conflicts []Conflict
	Notes     []string
	// TestError is nginx -t's [emerg] message: nginx won't (re)start with this config.
	TestError string
}

type Server struct {
	Names     []string
	Listens   []Listen
	Locations []*Location
	Cert      string
	Return    *Return // server-level return: applies before any location
	Pos       string
	// Shadowed holds, per port, the names an earlier server already claims there.
	Shadowed map[int][]string
}

// Ignored reports whether nginx never picks this server by name: on every port it
// listens on, all of its names belong to an earlier server.
func (s *Server) Ignored() bool {
	if len(s.Shadowed) == 0 || len(s.Names) == 0 {
		return false
	}
	for _, l := range s.Listens {
		if l.Unix == "" && len(s.Shadowed[l.Port]) < len(s.Names) {
			return false
		}
	}
	return true
}

type Listen struct {
	Addr    string // "" means all addresses
	Port    int
	Unix    string
	SSL     bool
	Default bool
}

func (l Listen) String() string {
	if l.Unix != "" {
		return "unix:" + l.Unix
	}
	s := ":" + strconv.Itoa(l.Port)
	switch l.Addr {
	case "", "*", "::", "0.0.0.0":
	default:
		if strings.Contains(l.Addr, ":") {
			s = "[" + l.Addr + "]" + s
		} else {
			s = l.Addr + s
		}
	}
	if l.SSL {
		s += " ssl"
	}
	return s
}

type Kind int

const (
	KindNone     Kind = iota
	KindProxy         // proxy_pass, grpc_pass, uwsgi_pass, scgi_pass
	KindFastCGI       // fastcgi_pass (php-fpm)
	KindStatic        // root / alias
	KindRedirect      // return 301/302/307/308
	KindReturn        // return with a non-redirect status
)

type Location struct {
	Mod      string // "", "=", "~", "~*", "^~"
	Path     string
	Kind     Kind
	Upstream *Upstream
	Root     string // directory for KindStatic (alias or root + path)
	Alias    bool
	Return   *Return
	Children []*Location
	Pos      string
}

func (l *Location) String() string {
	if l.Mod == "" {
		return l.Path
	}
	return l.Mod + " " + l.Path
}

type Upstream struct {
	Raw       string // as written in the config
	Directive string // proxy_pass, fastcgi_pass, ...
	Name      string // upstream {} block name, if it refers to one
	Endpoints []Endpoint
	Dynamic   bool // contains variables; resolved at request time
}

type Endpoint struct {
	Host string
	Port int
	Unix string
}

func (e Endpoint) String() string {
	if e.Unix != "" {
		return "unix:" + e.Unix
	}
	return e.Host + ":" + strconv.Itoa(e.Port)
}

type Return struct {
	Code int
	URL  string
}

// Conflict is two server blocks with the same name on the same port.
// nginx keeps the first one and ignores the second with only a warning.
type Conflict struct {
	Name    string
	Port    int
	Used    string
	Ignored string
}

func Build(dirs []*Directive) *Config {
	cfg := &Config{Upstreams: map[string][]Endpoint{}}
	for _, d := range dirs {
		if d.Name != "http" {
			continue
		}
		for _, u := range d.Block {
			if u.Name == "upstream" && len(u.Args) == 1 {
				cfg.Upstreams[u.Args[0]] = upstreamServers(u)
			}
		}
	}
	for _, d := range dirs {
		if d.Name != "http" {
			continue
		}
		root := directiveArg(d.Block, "root")
		for _, s := range d.Block {
			if s.Name == "server" && s.HasBlock {
				cfg.Servers = append(cfg.Servers, buildServer(cfg, s, root))
			}
		}
	}
	cfg.Conflicts = conflicts(cfg.Servers)
	return cfg
}

func upstreamServers(u *Directive) []Endpoint {
	var eps []Endpoint
	for _, s := range u.Block {
		if s.Name == "server" && len(s.Args) > 0 {
			if ep, ok := parseEndpoint(s.Args[0], 80); ok {
				eps = append(eps, ep)
			}
		}
	}
	return eps
}

func buildServer(cfg *Config, d *Directive, httpRoot string) *Server {
	s := &Server{Pos: d.Pos()}
	root := httpRoot
	if r := directiveArg(d.Block, "root"); r != "" {
		root = r
	}
	for _, c := range d.Block {
		switch c.Name {
		case "listen":
			if len(c.Args) > 0 {
				s.Listens = append(s.Listens, parseListen(c.Args))
			}
		case "server_name":
			s.Names = append(s.Names, c.Args...)
		case "ssl_certificate":
			if len(c.Args) > 0 && s.Cert == "" {
				s.Cert = c.Args[0]
			}
		case "return":
			if s.Return == nil {
				s.Return = parseReturn(c.Args)
			}
		case "location":
			if loc := buildLocation(cfg, c, root); loc != nil {
				s.Locations = append(s.Locations, loc)
			}
		}
	}
	if len(s.Listens) == 0 {
		s.Listens = []Listen{{Port: 80}}
	}
	if len(s.Locations) == 0 {
		loc := &Location{Path: "/", Pos: d.Pos()}
		if root != "" {
			loc.Kind, loc.Root = KindStatic, root
		}
		s.Locations = []*Location{loc}
	}
	return s
}

func buildLocation(cfg *Config, d *Directive, root string) *Location {
	if !d.HasBlock || len(d.Args) == 0 {
		return nil
	}
	loc := &Location{Pos: d.Pos()}
	if len(d.Args) >= 2 {
		loc.Mod, loc.Path = d.Args[0], d.Args[1]
	} else {
		loc.Path = d.Args[0]
		// "location ~^/api" is not valid nginx, but "location =/x" is.
		if strings.HasPrefix(loc.Path, "=") && len(loc.Path) > 1 {
			loc.Mod, loc.Path = "=", loc.Path[1:]
		}
	}
	if strings.HasPrefix(loc.Path, "@") {
		return nil // named locations are only reached through try_files/error_page
	}
	if r := directiveArg(d.Block, "root"); r != "" {
		root = r
	}
	for _, c := range d.Block {
		switch c.Name {
		case "proxy_pass", "grpc_pass", "uwsgi_pass", "scgi_pass", "fastcgi_pass":
			if len(c.Args) == 0 || loc.Kind == KindProxy || loc.Kind == KindFastCGI {
				continue
			}
			loc.Kind = KindProxy
			if c.Name == "fastcgi_pass" {
				loc.Kind = KindFastCGI
			}
			loc.Upstream = parseUpstream(cfg, c.Name, c.Args[0])
		case "return":
			if loc.Return == nil {
				loc.Return = parseReturn(c.Args)
			}
		case "alias":
			if len(c.Args) > 0 {
				loc.Root, loc.Alias = c.Args[0], true
			}
		case "location":
			if child := buildLocation(cfg, c, root); child != nil {
				loc.Children = append(loc.Children, child)
			}
		}
	}
	switch {
	case loc.Return != nil:
		// return runs in the rewrite phase, before proxying or serving files.
		loc.Kind, loc.Upstream = KindReturn, nil
		if loc.Return.Code >= 300 && loc.Return.Code < 400 {
			loc.Kind = KindRedirect
		}
	case loc.Kind != KindNone:
	case loc.Root != "":
		loc.Kind = KindStatic
	case root != "":
		loc.Kind, loc.Root = KindStatic, root
	}
	return loc
}

func parseListen(args []string) Listen {
	l := Listen{}
	a := args[0]
	switch {
	case strings.HasPrefix(a, "unix:"):
		l.Unix = strings.TrimPrefix(a, "unix:")
	case strings.HasPrefix(a, "["):
		if i := strings.Index(a, "]"); i >= 0 {
			l.Addr = a[1:i]
			l.Port = 80
			if p, err := strconv.Atoi(strings.TrimPrefix(a[i+1:], ":")); err == nil {
				l.Port = p
			}
		}
	default:
		if p, err := strconv.Atoi(a); err == nil {
			l.Port = p
		} else if host, port, ok := strings.Cut(a, ":"); ok {
			l.Addr = host
			l.Port, _ = strconv.Atoi(port)
		} else {
			l.Addr, l.Port = a, 80
		}
	}
	for _, f := range args[1:] {
		switch f {
		case "ssl", "quic":
			l.SSL = true
		case "default_server", "default":
			l.Default = true
		}
	}
	return l
}

func parseReturn(args []string) *Return {
	if len(args) == 0 {
		return nil
	}
	if code, err := strconv.Atoi(args[0]); err == nil {
		r := &Return{Code: code}
		if len(args) > 1 {
			r.URL = args[1]
		}
		return r
	}
	return &Return{Code: 302, URL: args[0]} // "return http://..." means 302
}

func parseUpstream(cfg *Config, directive, raw string) *Upstream {
	u := &Upstream{Raw: raw, Directive: directive}
	if strings.Contains(raw, "$") {
		u.Dynamic = true
		return u
	}
	rest := raw
	defPort := 80
	if scheme, after, ok := strings.Cut(raw, "://"); ok {
		rest = after
		switch scheme {
		case "https", "grpcs":
			defPort = 443
		}
	}
	if strings.HasPrefix(rest, "unix:") {
		// http://unix:/path/to.sock:/uri
		sock := strings.TrimPrefix(rest, "unix:")
		if i := strings.Index(sock, ":"); i >= 0 {
			sock = sock[:i]
		}
		u.Endpoints = []Endpoint{{Unix: sock}}
		return u
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if eps, ok := cfg.Upstreams[rest]; ok {
		u.Name = rest
		u.Endpoints = eps
		return u
	}
	if ep, ok := parseEndpoint(rest, defPort); ok {
		u.Endpoints = []Endpoint{ep}
	}
	return u
}

func parseEndpoint(s string, defPort int) (Endpoint, bool) {
	if strings.HasPrefix(s, "unix:") {
		return Endpoint{Unix: strings.TrimPrefix(s, "unix:")}, true
	}
	if s == "" {
		return Endpoint{}, false
	}
	if strings.HasPrefix(s, "[") {
		i := strings.Index(s, "]")
		if i < 0 {
			return Endpoint{}, false
		}
		ep := Endpoint{Host: s[1:i], Port: defPort}
		if p, err := strconv.Atoi(strings.TrimPrefix(s[i+1:], ":")); err == nil {
			ep.Port = p
		}
		return ep, true
	}
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return Endpoint{Host: s, Port: defPort}, true
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return Endpoint{}, false
	}
	return Endpoint{Host: host, Port: p}, true
}

func directiveArg(dirs []*Directive, name string) string {
	for _, d := range dirs {
		if d.Name == name && len(d.Args) > 0 {
			return d.Args[0]
		}
	}
	return ""
}

func conflicts(servers []*Server) []Conflict {
	type key struct {
		name string
		port int
	}
	first := map[key]*Server{}
	var out []Conflict
	for _, s := range servers {
		for _, n := range s.Names {
			if n == "" || n == "_" || strings.HasPrefix(n, "~") {
				continue
			}
			for _, l := range s.Listens {
				if l.Unix != "" {
					continue
				}
				k := key{strings.ToLower(n), l.Port}
				f, ok := first[k]
				switch {
				case !ok:
					first[k] = s
				case f != s && !containsStr(s.Shadowed[l.Port], n):
					out = append(out, Conflict{Name: n, Port: l.Port, Used: f.Pos, Ignored: s.Pos})
					if s.Shadowed == nil {
						s.Shadowed = map[int][]string{}
					}
					s.Shadowed[l.Port] = append(s.Shadowed[l.Port], n)
				}
			}
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (s *Server) DisplayName() string {
	for _, n := range s.Names {
		if n != "" && n != "_" {
			return n
		}
	}
	return "(default)"
}

func (s *Server) ListenSummary() string {
	var parts []string
	for _, l := range s.Listens {
		str := l.String()
		dup := false
		for _, p := range parts {
			if p == str {
				dup = true
			}
		}
		if !dup {
			parts = append(parts, str)
		}
	}
	return strings.Join(parts, " ")
}

func (l *Location) Target() string {
	switch l.Kind {
	case KindProxy, KindFastCGI:
		return l.Upstream.Raw
	case KindStatic:
		return l.Root
	case KindRedirect:
		return fmt.Sprintf("%d %s", l.Return.Code, l.Return.URL)
	case KindReturn:
		if l.Return.URL != "" {
			return fmt.Sprintf("return %d %q", l.Return.Code, l.Return.URL)
		}
		return fmt.Sprintf("return %d", l.Return.Code)
	}
	return "(nothing)"
}
