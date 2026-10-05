package process

import "testing"

func TestLabel(t *testing.T) {
	if got := (Owner{PID: 42, Name: "node"}).Label(); got != "node (pid 42)" {
		t.Errorf("got %q", got)
	}
	if got := (Owner{PID: 42, Name: "api", Unit: "api.service"}).Label(); got != "systemd: api.service" {
		t.Errorf("got %q", got)
	}
}

func TestProgram(t *testing.T) {
	for cmd, want := range map[string]string{
		"/usr/bin/python3 -u /srv/app/manage.py runserver": "manage",
		"/opt/my-api/bin/server --port 8080":               "server",
		"node --enable-source-maps dist/main.js":           "main",
		"/opt/homebrew/Python -m http.server 9123":         "http.server",
	} {
		if got := (Owner{Cmdline: cmd}).Program(); got != want {
			t.Errorf("%s: got %s want %s", cmd, got, want)
		}
	}
}
