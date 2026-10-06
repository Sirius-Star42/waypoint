package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Sirius-Star42/waypoint/internal/diagnosis"
	"github.com/Sirius-Star42/waypoint/internal/render"
	"github.com/Sirius-Star42/waypoint/internal/runner"
)

var ExitProblems = errors.New("problems found")

type options struct {
	verbose bool
	timeout time.Duration
	nginx   string
	mermaid bool
	open    bool
}

func New(version string, stdout io.Writer) *cobra.Command {
	o := &options{}
	root := &cobra.Command{
		Use:   "waypoint [target]",
		Short: "See where requests go on your machine or server, and why they break",
		Long: `waypoint maps your nginx routes to the apps, containers and services behind them,
checks every hop against what is actually running, and explains what is broken.

  waypoint                      every site, the app behind it and how it runs
  waypoint 8080                 why isn't localhost:8080 working?
  waypoint api.example.com      trace a domain through nginx to the app
  waypoint https://x.dev/api    trace one URL, including the nginx location
  waypoint map --open           the route map as a diagram in your browser
  waypoint map --mermaid        the route map as Mermaid, to paste into a README`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("give one target at a time, e.g. waypoint 8080 or waypoint %s", args[0])
			}
			return nil
		},
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				return o.diagnose(cmd.Context(), stdout, args[0])
			}
			return o.overview(cmd.Context(), stdout)
		},
	}
	root.PersistentFlags().BoolVarP(&o.verbose, "verbose", "v", false, "show evidence and full logs")
	root.PersistentFlags().DurationVar(&o.timeout, "timeout", 3*time.Second, "timeout for each network check")
	root.PersistentFlags().StringVar(&o.nginx, "nginx", "", "path to nginx.conf (default: auto-detect)")

	mapCmd := &cobra.Command{
		Use:   "map",
		Short: "Show every site, the app behind it and how it runs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.routeMap(cmd.Context(), stdout)
		},
	}
	mapCmd.Flags().BoolVar(&o.mermaid, "mermaid", false, "print the map as a Mermaid diagram (renders on GitHub)")
	mapCmd.Flags().BoolVar(&o.open, "open", false, "open the map as a diagram on mermaid.live (prints the link over SSH)")
	root.AddCommand(mapCmd)
	root.SetOut(stdout)
	return root
}

func (o *options) env(ctx context.Context) *diagnosis.Env {
	dir, _ := os.Getwd()
	e := diagnosis.NewEnv(ctx, runner.Exec{}, o.timeout, dir)
	e.NginxPath = o.nginx
	return e
}

func (o *options) diagnose(ctx context.Context, w io.Writer, arg string) error {
	t, err := diagnosis.ParseTarget(arg)
	if err != nil {
		return err
	}
	e := o.env(ctx)
	r := e.Diagnose(t)
	p := render.New(w, o.verbose)
	p.Diagnose(r)
	notes(p, e)
	if !r.OK() {
		return ExitProblems
	}
	return nil
}

func (o *options) overview(ctx context.Context, w io.Writer) error {
	return o.routeMap(ctx, w)
}

func (o *options) routeMap(ctx context.Context, w io.Writer) error {
	e := o.env(ctx)
	r, err := e.Map()
	if err != nil {
		return err
	}
	inv := e.Inventory()
	if o.open {
		link := render.MermaidLink(r, inv)
		if !openBrowser(link) {
			fmt.Fprintln(w, "Open this link in a browser to see the map:")
		}
		fmt.Fprintln(w, link)
		return nil
	}
	if o.mermaid {
		render.Mermaid(w, r, inv)
		// stderr, so `waypoint map --mermaid > map.md` stays a clean diagram.
		fmt.Fprintf(os.Stderr, "\nView it in your browser (the diagram travels inside the link, nothing is uploaded):\n%s\n", render.MermaidLink(r, inv))
		return nil
	}
	issues := merge(r, inv)
	p := render.New(w, o.verbose)
	if r == nil {
		fmt.Fprintln(w, "No nginx found on this machine; showing what runs here. Use --nginx <path> to point at a config.")
		fmt.Fprintln(w)
	}
	p.Overview(r, inv, issues)
	notes(p, e)
	if len(issues) > 0 {
		return ExitProblems
	}
	return nil
}

// openBrowser opens url locally; over SSH there is no browser to open, so the caller prints it.
func openBrowser(url string) bool {
	if os.Getenv("SSH_CONNECTION") != "" {
		return false
	}
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	return exec.Command(name, url).Run() == nil
}

func merge(r *diagnosis.MapReport, inv *diagnosis.Inventory) []*diagnosis.Finding {
	var out []*diagnosis.Finding
	if r != nil {
		out = append(out, r.Issues...)
	}
	for _, f := range inv.Issues {
		dup := false
		for _, g := range out {
			if strings.HasSuffix(g.Title, f.Title) || f.Code != "" && f.Code == g.Code {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	inv.Hint(out)
	return out
}

func notes(p *render.Printer, e *diagnosis.Env) {
	if n := e.Notes(); len(n) > 0 {
		fmt.Fprintln(p.W)
		p.Notes(n)
	}
}
