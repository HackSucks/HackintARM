package nameunicode

import (
	"reflect"
	"testing"
)

func TestCanonicalPipelines(t *testing.T) {
	for _, c := range []struct {
		input string
		fold  bool
		want  string
	}{{"", true, ""}, {"AßΣς", true, "assσσ"}, {"é", false, "e\u0301"}, {"\u0345\u0300", true, "\u0300ι"}, {"각가", false, "각가"}, {"a\u0315\u0300\u0300", false, "a\u0300\u0300\u0315"}, {"\uFFFD", false, "\uFFFD"}} {
		if got := string(APFS(c.input, c.fold)); got != c.want {
			t.Errorf("APFS(%q,%v)=%q want%q", c.input, c.fold, got, c.want)
		}
	}
	for _, s := range []string{"", "abc", "é", "각가", "\U0001109A", "\u212B", "a\u0315\u0300"} {
		n := HFS(s)
		if HFS(n) != n {
			t.Fatalf("HFS normalization not idempotent:%q", s)
		}
	}
	if !reflect.DeepEqual(APFS("a\u0300\u0315", false), APFS("a\u0315\u0300", false)) {
		t.Fatal("canonical ordering")
	}
}

func TestHFSEscapedByteConversion(t *testing.T) {
	for _, c := range [][2]string{{"x\x80y", "x%80y"}, {"x\ufffey", "x%EF%BF%BEy"}, {"x\uffffy", "x%EF%BF%BFy"}, {"x�y", "x�y"}, {"x\xc3", "x%C3"}, {"\U0010FFFF", "\U0010FFFF"}} {
		if got := HFS(c[0]); got != c[1] {
			t.Fatalf("HFS(%x)=%q want%q", c[0], got, c[1])
		}
	}
}
