package usage

import "testing"

func TestParseDockerStats(t *testing.T) {
	got := ParseDockerStats("bd3db86c9e8a\t1.25%\t12.5MiB / 12.65GiB\n512d60e4dd07\t0.00%\t0B / 0B\nbad line\n")
	if u := got["bd3db86c9e8a"]; u.CPU != 1.25 || u.Mem != 12.5*(1<<20) {
		t.Errorf("bd3db86c9e8a = %+v", u)
	}
	if u, ok := got["512d60e4dd07"]; !ok || u.Mem != 0 {
		t.Errorf("512d60e4dd07 = %+v", u)
	}
}

func TestParsePS(t *testing.T) {
	got := ParsePS("    1   0.1  18880\n93830  12.5   3296\n")
	if u := got[93830]; u.CPU != 12.5 || u.Mem != 3296<<10 {
		t.Errorf("93830 = %+v", u)
	}
}

func TestString(t *testing.T) {
	if s := (Usage{CPU: 3.14, Mem: 1536 << 20}).String(); s != "cpu 3.1% · mem 1.5 GiB" {
		t.Errorf("String() = %q", s)
	}
}
