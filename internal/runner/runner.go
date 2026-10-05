package runner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	Combined(ctx context.Context, name string, args ...string) (string, error)
	Has(name string) bool
}

type Exec struct{}

func (Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), errors.New(msg)
	}
	return stdout.String(), nil
}

func (Exec) Combined(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func (Exec) Has(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

type Fake struct {
	Out   map[string]string
	Err   map[string]error
	Tools map[string]bool
}

func (f Fake) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if err, ok := f.Err[key]; ok {
		return f.Out[key], err
	}
	if out, ok := f.Out[key]; ok {
		return out, nil
	}
	return "", errors.New("fake: no output for " + key)
}

func (f Fake) Combined(ctx context.Context, name string, args ...string) (string, error) {
	return f.Run(ctx, name, args...)
}

func (f Fake) Has(name string) bool { return f.Tools[name] }
