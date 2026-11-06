package apfs

import (
	"testing"
	"unicode/utf16"
)

func TestNameHashInputBoundaries(t *testing.T) {
	for _, fold := range []bool{false, true} {
		want := CalculateNameHash([]byte("name"), fold)
		for _, input := range [][]byte{[]byte("name\x00suffix"), []byte("name\xffsuffix")} {
			if CalculateNameHash(input, fold) != want {
				t.Fatal("legacy byte boundary changed")
			}
		}
		if CalculateNameHashFromUTF16(append(utf16.Encode([]rune("name")), 0, 'x'), fold) != want {
			t.Fatal("UTF16 NUL boundary")
		}
		if CalculateNameHash([]byte("�"), fold) == CalculateNameHash(nil, fold) {
			t.Fatal("valid replacement scalar discarded")
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"a", "b", -1}, {"b", "a", 1}, {"a", "a", 0}, {"", "a", -1}, {"a", "", 1}} {
		if got := CompareNamesWithUTF8([]byte(c.a), []byte(c.b), false); got != c.want {
			t.Fatal(got, c.want)
		}
	}
}

func TestNameEncodingComparison(t *testing.T) {
	for _, s := range []string{"", "ascii", "é", "😀", "\uFFFD"} {
		if got := UTF16ToString(StringToUTF16(s)); got != s {
			t.Fatal(got, s)
		}
	}
	for _, fold := range []bool{false, true} {
		for _, pair := range [][2]string{{"a", "b"}, {"b", "a"}, {"a", "a"}, {"é", "e\u0301"}, {"ß", "ss"}} {
			got := CompareNamesWithUTF16(StringToUTF16(pair[0]), StringToUTF16(pair[1]), fold)
			want := CompareNamesWithUTF8([]byte(pair[0]), []byte(pair[1]), fold)
			if got != want {
				t.Fatal(got, want)
			}
		}
	}
}
