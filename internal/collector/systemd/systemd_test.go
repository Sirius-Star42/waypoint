package systemd

import (
	"context"
	"testing"

	"github.com/Sirius-Star42/waypoint/internal/runner"
)

const failedShow = `ActiveState=activating
SubState=auto-restart
Result=exit-code
ExecMainStatus=1
NRestarts=12
StateChangeTimestamp=Mon 2026-10-05 19:01:22 UTC
LoadState=loaded
FragmentPath=/etc/systemd/system/my-api.service
ExecStart={ path=/opt/my-api/bin/server ; argv[]=/opt/my-api/bin/server --port 8080 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
WorkingDirectory=/opt/my-api
User=deploy
ActiveEnterTimestamp=Mon 2026-09-21 08:00:00 UTC
`

func TestForPort(t *testing.T) {
	s := &Systemd{
		Runner: runner.Fake{Out: map[string]string{
			"systemctl show my-api.service --no-pager -p " + props: failedShow,
		}},
		Dirs: []string{"testdata"},
	}
	units := s.ForPort(context.Background(), 8080)
	if len(units) != 1 || units[0].Name != "my-api.service" {
		t.Fatalf("units = %+v", units)
	}
	u := units[0]
	if !u.Down() || u.StateText() != "activating (auto-restart), exit-code 1, restarted 12×" {
		t.Errorf("state = %q", u.StateText())
	}
	if u.Exec != "/opt/my-api/bin/server --port 8080" || u.Dir != "/opt/my-api" || u.User != "deploy" || u.Started.Day() != 21 {
		t.Errorf("details = %+v", u)
	}
}
