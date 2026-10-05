package process

import "testing"

func TestParseCgroup(t *testing.T) {
	tests := []struct{ in, unit, container string }{
		{"0::/system.slice/my-api.service\n", "my-api.service", ""},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/dev.service\n", "dev.service", ""},
		{"0::/system.slice/docker-" + id + ".scope\n", "", id},
		{"12:pids:/docker/" + id + "\n", "", id},
		{"0::/user.slice/user-1000.slice/session-3.scope\n", "", ""},
	}
	for _, tt := range tests {
		u, c := parseCgroup(tt.in)
		if u != tt.unit || c != tt.container {
			t.Errorf("%q: got (%q, %q)", tt.in, u, c)
		}
	}
}

func TestDecodeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F":                         "127.0.0.1",
		"00000000":                         "*",
		"00000000000000000000000000000000": "*",
		"00000000000000000000000001000000": "::1",
	} {
		if got := decodeAddr(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

const id = "3f4e1b2c9d8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e"
