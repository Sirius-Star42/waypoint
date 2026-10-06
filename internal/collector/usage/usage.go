// Package usage reads CPU and memory use of processes and containers.
package usage

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sirius-Star42/waypoint/internal/runner"
)

type Usage struct {
	CPU float64 // percent of one core
	Mem uint64  // bytes
}

func (u Usage) String() string {
	return fmt.Sprintf("cpu %.1f%% · mem %s", u.CPU, Bytes(u.Mem))
}

func (u Usage) Add(o Usage) Usage { return Usage{u.CPU + o.CPU, u.Mem + o.Mem} }

func Bytes(n uint64) string {
	const mib = 1 << 20
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= mib:
		return fmt.Sprintf("%d MiB", n/mib)
	}
	return fmt.Sprintf("%d KiB", n>>10)
}

// Containers returns the usage of running containers by short (12 character) ID.
func Containers(ctx context.Context, r runner.Runner) map[string]Usage {
	out, err := r.Run(ctx, "docker", "stats", "--no-stream", "--format", "{{.ID}}\t{{.CPUPerc}}\t{{.MemUsage}}")
	if err != nil {
		return nil
	}
	return ParseDockerStats(out)
}

// ParseDockerStats reads lines like "bd3db86c9e8a\t0.35%\t12.95MiB / 12.65GiB".
func ParseDockerStats(out string) map[string]Usage {
	res := map[string]Usage{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		cpu, err := strconv.ParseFloat(strings.TrimSuffix(f[1], "%"), 64)
		if err != nil {
			continue
		}
		used, _, _ := strings.Cut(f[2], " / ")
		mem, ok := parseSize(strings.TrimSpace(used))
		if !ok {
			continue
		}
		res[f[0]] = Usage{CPU: cpu, Mem: mem}
	}
	return res
}

func parseSize(s string) (uint64, bool) {
	units := []struct {
		suffix string
		mult   float64
	}{
		{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40},
		{"kB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12}, {"B", 1},
	}
	for _, u := range units {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, false
			}
			return uint64(v * u.mult), true
		}
	}
	return 0, false
}

// Processes returns the usage of the given pids. ps reports CPU averaged over the process
// lifetime on Linux and recent CPU on macOS.
func Processes(ctx context.Context, r runner.Runner, pids []int) map[int]Usage {
	if len(pids) == 0 {
		return nil
	}
	var list []string
	for _, p := range pids {
		list = append(list, strconv.Itoa(p))
	}
	out, _ := r.Run(ctx, "ps", "-o", "pid=,pcpu=,rss=", "-p", strings.Join(list, ","))
	return ParsePS(out)
}

// ParsePS reads "pid %cpu rss-in-KiB" lines.
func ParsePS(out string) map[int]Usage {
	res := map[int]Usage{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		cpu, err2 := strconv.ParseFloat(f[1], 64)
		rss, err3 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		res[pid] = Usage{CPU: cpu, Mem: rss << 10}
	}
	return res
}
