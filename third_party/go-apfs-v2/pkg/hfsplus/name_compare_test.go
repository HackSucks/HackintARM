package hfsplus

import (
	"testing"
)

func TestSharedNameComparison(t *testing.T) {
	for _, c := range []struct {
		a, b      string
		sensitive bool
		want      int
	}{{"", "", false, 0}, {"a", "", false, 1}, {"", "a", false, -1}, {"a", "b", false, -1}, {"b", "a", false, 1}, {"A", "a", false, 0}, {"A", "a", true, -1}, {"a\u200d", "a", false, 0}, {"a", "a\u200d", false, 0}, {"Đ", "đ", false, 0}, {"Σ", "ς", false, 1}, {"ß", "ss", false, 1}, {"é", "e\u0301", true, 0}, {"a:b", "a:b", false, 0}} {
		if got := CompareNames(c.a, c.b, c.sensitive); got != c.want {
			t.Errorf("%q %q sensitive%v got%d want%d", c.a, c.b, c.sensitive, got, c.want)
		}
	}
	if compareNameUnits([]uint16{0}, []uint16{0xffff}, false) != 0 {
		t.Fatal("native catalog NUL mapping")
	}
}
