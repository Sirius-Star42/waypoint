package process

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// list reads /proc directly: /proc/net/tcp{,6} gives listening sockets and their
// inodes, /proc/<pid>/fd maps inodes to processes. Processes of other users are
// invisible without root.
func (f *Finder) list(context.Context) ([]Listener, error) {
	socks := append(listening("/proc/net/tcp"), listening("/proc/net/tcp6")...)
	owners := socketOwners()
	boot := bootTime()
	described := map[int]*Owner{}
	seen := map[string]bool{}
	var out []Listener
	for _, s := range socks {
		key := s.addr + ":" + strconv.Itoa(s.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		l := Listener{Addr: s.addr, Port: s.port}
		if pid, ok := owners[s.inode]; ok {
			if described[pid] == nil {
				described[pid] = describe(pid, boot)
			}
			l.Owner = described[pid]
		}
		out = append(out, l)
	}
	return out, nil
}

type sock struct {
	addr  string
	port  int
	inode int
}

func listening(path string) []sock {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var out []sock
	sc := bufio.NewScanner(file)
	sc.Scan()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(hexPort, 16, 32)
		if err != nil {
			continue
		}
		ino, _ := strconv.Atoi(f[9])
		out = append(out, sock{addr: decodeAddr(hexAddr), port: int(port), inode: ino})
	}
	return out
}

// decodeAddr turns /proc/net/tcp's little-endian hex words into an IP string.
func decodeAddr(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b)%4 != 0 {
		return ""
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip := net.IP(b)
	if ip.IsUnspecified() {
		return "*"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func socketOwners() map[int]int {
	m := map[int]int{}
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range procs {
		pid, err := strconv.Atoi(filepath.Base(p))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(p + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(p + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if ino, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")); err == nil {
				if _, seen := m[ino]; !seen {
					m[ino] = pid
				}
			}
		}
	}
	return m
}

func describe(pid int, boot time.Time) *Owner {
	o := &Owner{PID: pid}
	dir := "/proc/" + strconv.Itoa(pid)
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		o.Name = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		o.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	}
	o.Exe, _ = os.Readlink(dir + "/exe")
	o.Cwd, _ = os.Readlink(dir + "/cwd")
	if b, err := os.ReadFile(dir + "/cgroup"); err == nil {
		o.Unit, o.ContainerID = parseCgroup(string(b))
	}
	if b, err := os.ReadFile(dir + "/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "Uid:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					o.User = f[0]
					if u, err := user.LookupId(f[0]); err == nil {
						o.User = u.Username
					}
				}
			}
		}
	}
	if b, err := os.ReadFile(dir + "/stat"); err == nil && !boot.IsZero() {
		s := string(b)
		if i := strings.LastIndexByte(s, ')'); i >= 0 {
			f := strings.Fields(s[i+1:])
			if len(f) > 19 {
				if ticks, err := strconv.ParseInt(f[19], 10, 64); err == nil {
					o.Started = boot.Add(time.Duration(ticks) * time.Second / 100)
				}
			}
		}
	}
	return o
}

func bootTime() time.Time {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(n, 0)
			}
		}
	}
	return time.Time{}
}

var containerID = regexp.MustCompile(`(?:docker-|docker/|libpod-|containerd/|cri-containerd-)([0-9a-f]{64})`)

func parseCgroup(s string) (unit, container string) {
	for _, line := range strings.Split(s, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		segs := strings.Split(path, "/")
		for i := len(segs) - 1; i >= 0; i-- {
			seg := segs[i]
			if strings.HasSuffix(seg, ".service") && !strings.HasPrefix(seg, "user@") && seg != "docker.service" && seg != "containerd.service" {
				return seg, ""
			}
		}
		if m := containerID.FindStringSubmatch(path); m != nil {
			return "", m[1]
		}
	}
	return "", ""
}
