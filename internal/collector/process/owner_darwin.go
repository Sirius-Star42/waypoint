package process

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// list uses lsof. Without root it only sees the current user's processes.
func (f *Finder) list(ctx context.Context) ([]Listener, error) {
	out, _ := f.Runner.Run(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn")
	ls := parseLsof(out)
	var pids []string
	owners := map[int]*Owner{}
	for _, l := range ls {
		if l.Owner != nil && owners[l.Owner.PID] == nil {
			owners[l.Owner.PID] = l.Owner
			pids = append(pids, strconv.Itoa(l.Owner.PID))
		}
	}
	if len(pids) == 0 {
		return ls, nil
	}
	list := strings.Join(pids, ",")
	if ps, err := f.Runner.Run(ctx, "ps", "-o", "pid=,user=,lstart=,command=", "-p", list); err == nil {
		parsePS(ps, owners)
	}
	if out, err := f.Runner.Run(ctx, "lsof", "-a", "-d", "cwd,txt", "-Fpfn", "-p", list); err == nil || out != "" {
		parseFiles(out, owners)
	}
	return ls, nil
}

func parseLsof(out string) []Listener {
	var ls []Listener
	var cur *Owner
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if len(l) < 2 {
			continue
		}
		switch l[0] {
		case 'p':
			pid, _ := strconv.Atoi(l[1:])
			cur = &Owner{PID: pid}
		case 'c':
			if cur != nil {
				cur.Name = l[1:]
			}
		case 'n':
			i := strings.LastIndexByte(l, ':')
			if i < 0 || cur == nil {
				continue
			}
			port, err := strconv.Atoi(l[i+1:])
			if err != nil {
				continue
			}
			addr := strings.Trim(l[1:i], "[]")
			if addr == "::" || addr == "0.0.0.0" {
				addr = "*"
			}
			key := addr + ":" + l[i+1:]
			if seen[key] {
				continue
			}
			seen[key] = true
			ls = append(ls, Listener{Addr: addr, Port: port, Owner: cur})
		}
	}
	return ls
}

func parsePS(out string, owners map[int]*Owner) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 8 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		o := owners[pid]
		if err != nil || o == nil {
			continue
		}
		o.User = f[1]
		if t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(f[2:7], " "), time.Local); err == nil {
			o.Started = t
		}
		o.Cmdline = strings.Join(f[7:], " ")
		if strings.HasPrefix(f[7], "/") {
			o.Exe = f[7]
		}
	}
}

// parseFiles reads cwd and the executable (first txt entry) from lsof output.
func parseFiles(out string, owners map[int]*Owner) {
	var cur *Owner
	fd := ""
	exeSet := map[*Owner]bool{}
	for _, l := range strings.Split(out, "\n") {
		if len(l) < 2 {
			continue
		}
		switch l[0] {
		case 'p':
			pid, _ := strconv.Atoi(l[1:])
			cur = owners[pid]
		case 'f':
			fd = l[1:]
		case 'n':
			if cur == nil {
				continue
			}
			switch {
			case fd == "cwd":
				cur.Cwd = l[1:]
			case fd == "txt" && !exeSet[cur]:
				cur.Exe, exeSet[cur] = l[1:], true
			}
		}
	}
}
