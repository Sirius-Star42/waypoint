package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/Sirius-Star42/waypoint/internal/cli"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	err := cli.New(version, os.Stdout).ExecuteContext(ctx)
	switch {
	case err == nil:
	case errors.Is(err, cli.ExitProblems):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "waypoint:", err)
		os.Exit(2)
	}
}
