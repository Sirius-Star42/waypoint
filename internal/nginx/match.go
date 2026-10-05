package nginx

import (
	"regexp"
	"strings"
)

type Match struct {
	Server       *Server
	Location     *Location // nil when the server returns before location matching
	ServerReason string
}

func (c *Config) Route(host string, port int, path string) *Match {
	s, why := c.findServer(host, port)
	if s == nil {
		return nil
	}
	m := &Match{Server: s, ServerReason: why}
	if s.Return != nil {
		return m
	}
	if path == "" {
		path = "/"
	}
	m.Location, _ = findLocation(s.Locations, path)
	return m
}

// findServer implements server_name selection:
// exact name, longest leading wildcard, longest trailing wildcard,
// first matching regex, then the default server for the port.
func (c *Config) findServer(host string, port int) (*Server, string) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	var cands []*Server
	for _, s := range c.Servers {
		for _, l := range s.Listens {
			if l.Unix == "" && l.Port == port {
				cands = append(cands, s)
				break
			}
		}
	}
	if len(cands) == 0 {
		return nil, ""
	}
	for _, s := range cands {
		for _, n := range s.Names {
			if strings.ToLower(n) == host || (strings.HasPrefix(n, ".") && strings.ToLower(n[1:]) == host) {
				return s, "exact name"
			}
		}
	}
	var best *Server
	bestLen := 0
	for _, s := range cands {
		for _, n := range s.Names {
			n = strings.ToLower(n)
			var suffix string
			switch {
			case strings.HasPrefix(n, "*."):
				suffix = n[1:]
			case strings.HasPrefix(n, "."):
				suffix = n
			default:
				continue
			}
			if strings.HasSuffix(host, suffix) && len(suffix) > bestLen {
				best, bestLen = s, len(suffix)
			}
		}
	}
	if best != nil {
		return best, "wildcard name"
	}
	for _, s := range cands {
		for _, n := range s.Names {
			n = strings.ToLower(n)
			if strings.HasSuffix(n, ".*") {
				prefix := n[:len(n)-1]
				if strings.HasPrefix(host, prefix) && len(prefix) > bestLen {
					best, bestLen = s, len(prefix)
				}
			}
		}
	}
	if best != nil {
		return best, "wildcard name"
	}
	for _, s := range cands {
		for _, n := range s.Names {
			if !strings.HasPrefix(n, "~") {
				continue
			}
			if re, err := regexp.Compile("(?i)" + n[1:]); err == nil && re.MatchString(host) {
				return s, "regex name"
			}
		}
	}
	for _, s := range cands {
		for _, l := range s.Listens {
			if l.Port == port && l.Default {
				return s, "default_server"
			}
		}
	}
	return cands[0], "first server on port"
}

// findLocation follows ngx_http_core_find_location: exact match wins; otherwise
// the longest prefix is remembered and its nested locations searched; "^~" stops
// there; otherwise regex locations are tried in config order and the first match
// wins. The bool reports whether the match is final (no regex may override it).
func findLocation(locs []*Location, uri string) (*Location, bool) {
	for _, l := range locs {
		if l.Mod == "=" && l.Path == uri {
			return l, true
		}
	}
	var prefix *Location
	for _, l := range locs {
		if (l.Mod == "" || l.Mod == "^~") && strings.HasPrefix(uri, l.Path) {
			if prefix == nil || len(l.Path) > len(prefix.Path) {
				prefix = l
			}
		}
	}
	found := prefix
	if prefix != nil {
		if len(prefix.Children) > 0 {
			nested, final := findLocation(prefix.Children, uri)
			if final {
				return nested, true
			}
			if nested != nil {
				found = nested
			}
		}
		if prefix.Mod == "^~" {
			return found, true
		}
	}
	for _, l := range locs {
		if l.Mod != "~" && l.Mod != "~*" {
			continue
		}
		expr := l.Path
		if l.Mod == "~*" {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil || !re.MatchString(uri) {
			continue
		}
		if nested, _ := findLocation(l.Children, uri); nested != nil {
			return nested, true
		}
		return l, true
	}
	return found, false
}
