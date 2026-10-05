package diagnosis

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Target struct {
	Raw       string
	Scheme    string // "" when not given
	Host      string
	Port      int
	Path      string
	PortGiven bool
}

func (t Target) HostPort() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

func (t Target) URL() string {
	scheme := t.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := t.Host
	if (scheme == "http" && t.Port != 80) || (scheme == "https" && t.Port != 443) {
		host = t.HostPort()
	}
	return scheme + "://" + host + t.Path
}

func ParseTarget(s string) (Target, error) {
	t := Target{Raw: s}
	s = strings.TrimSpace(s)
	if s == "" {
		return t, fmt.Errorf("empty target")
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(s, ":")); err == nil {
		if n <= 0 || n > 65535 {
			return t, fmt.Errorf("invalid port %d", n)
		}
		t.Host, t.Port, t.Path, t.PortGiven = "localhost", n, "/", true
		return t, nil
	}
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return t, fmt.Errorf("can't understand %q; try a port (8080), host:port or URL", t.Raw)
	}
	t.Scheme = strings.ToLower(u.Scheme)
	if t.Scheme != "" && t.Scheme != "http" && t.Scheme != "https" {
		return t, fmt.Errorf("unsupported scheme %q; use http or https", u.Scheme)
	}
	t.Host = u.Hostname()
	t.Path = u.EscapedPath()
	if u.RawQuery != "" {
		t.Path += "?" + u.RawQuery
	}
	if t.Path == "" {
		t.Path = "/"
	}
	if p := u.Port(); p != "" {
		t.Port, err = strconv.Atoi(p)
		if err != nil || t.Port <= 0 || t.Port > 65535 {
			return t, fmt.Errorf("invalid port %q", p)
		}
		t.PortGiven = true
	} else {
		switch t.Scheme {
		case "https":
			t.Port = 443
		default:
			t.Port = 80
		}
	}
	return t, nil
}

func (t Target) pathOnly() string {
	p, _, _ := strings.Cut(t.Path, "?")
	if u, err := url.PathUnescape(p); err == nil {
		return u
	}
	return p
}
