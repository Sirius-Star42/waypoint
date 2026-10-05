package process

import "testing"

func TestParseLsof(t *testing.T) {
	ls := parseLsof("p8123\ncnode\nf23\nn*:3000\nf24\nn[::]:3000\np9000\ncpostgres\nf5\nn127.0.0.1:5432\n")
	if len(ls) != 2 {
		t.Fatalf("got %+v", ls)
	}
	if ls[0].Port != 3000 || ls[0].Addr != "*" || ls[0].Owner.Name != "node" {
		t.Errorf("first = %+v", ls[0])
	}
	if !ls[1].LocalOnly() || ls[1].Owner.PID != 9000 {
		t.Errorf("second = %+v", ls[1])
	}
	owners := map[int]*Owner{8123: ls[0].Owner}
	parsePS("8123 deploy  Mon Oct  5 19:01:22 2026 /usr/local/bin/node server.js --port 3000\n", owners)
	o := owners[8123]
	if o.User != "deploy" || o.Started.Day() != 5 || o.Exe != "/usr/local/bin/node" || o.Program() != "server" {
		t.Errorf("owner = %+v program=%s", o, o.Program())
	}
	parseFiles("p8123\nfcwd\nn/srv/app\nftxt\nn/opt/node/bin/node\nftxt\nn/usr/lib/dyld\n", owners)
	if o.Cwd != "/srv/app" || o.Exe != "/opt/node/bin/node" {
		t.Errorf("cwd = %q exe = %q", o.Cwd, o.Exe)
	}
}
