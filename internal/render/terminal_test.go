package render

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Sirius-Star42/waypoint/internal/diagnosis"
)

func TestAppsWithNothingRunning(t *testing.T) {
	inv := &diagnosis.Inventory{
		Apps: []*diagnosis.App{
			{Name: "shop", Kind: "docker compose", Stopped: true, StoppedAt: time.Now().Add(-3 * time.Hour),
				Facts: []diagnosis.Fact{{Label: "file", Value: "/srv/shop/compose.yaml"}}},
			{Name: "legacy", Kind: "docker compose", Stopped: true},
		},
		Stopped: []diagnosis.StoppedContainer{{Name: "scratch", State: "exited (code 1)"}},
		System:  []string{"rapportd :51801", "sharingd :8770"},
	}
	var buf bytes.Buffer
	New(&buf, false).Overview(nil, inv, nil)
	out := buf.String()
	for _, want := range []string{
		"APPS  nothing running · 2 stopped compose projects · 1 old container\n",
		"  NAME     STOPPED       COMPOSE FILE\n",
		"  shop     3 hours ago   /srv/shop/compose.yaml\n",
		"  legacy   unknown\n",
		"  scratch   exited (code 1)   unknown\n",
		"2 system processes hidden (-v to show)",
		"✓ no problems · nothing is running\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rapportd") {
		t.Errorf("system processes should be hidden without -v:\n%s", out)
	}
}

func TestMermaidCollapsesStoppedProjects(t *testing.T) {
	inv := &diagnosis.Inventory{Apps: []*diagnosis.App{
		{Name: "shop", Kind: "docker compose", Stopped: true, State: "stopped 2 days ago",
			Services: []*diagnosis.AppService{{Name: "api", State: "finished 2 days ago"}, {Name: "db", State: "stopped 2 days ago"}}},
	}}
	var buf bytes.Buffer
	Mermaid(&buf, nil, inv)
	out := buf.String()
	if !strings.Contains(out, `n0["shop<br/>docker compose · 2 services<br/>stopped 2 days ago"]`) || strings.Contains(out, "api") {
		t.Errorf("a stopped project should be a single node:\n%s", out)
	}
}

func TestMermaidLinkRoundTrip(t *testing.T) {
	inv := &diagnosis.Inventory{Apps: []*diagnosis.App{{Name: "shop", Kind: "process", State: "running"}}}
	link := MermaidLink(nil, inv)
	enc, ok := strings.CutPrefix(link, "https://mermaid.live/edit#pako:")
	if !ok {
		t.Fatalf("link = %s", link)
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(zr)
	var state struct{ Code string }
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(state.Code, "flowchart LR\n") || !strings.Contains(state.Code, "shop") {
		t.Errorf("code = %q", state.Code)
	}
}
