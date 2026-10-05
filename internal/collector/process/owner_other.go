//go:build !linux && !darwin

package process

import (
	"context"
	"errors"
)

func (f *Finder) list(context.Context) ([]Listener, error) {
	return nil, errors.New("finding port owners is supported on Linux and macOS only")
}
