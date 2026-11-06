package tools

import "testing"

func TestSanitizePathWindows(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		changed bool
	}{
		{"normal.txt", "normal.txt", false},
		{"dir/sub/file", "dir/sub/file", false},
		{"ünïcødé/файл.txt", "ünïcødé/файл.txt", false}, // valid on NTFS
		// Single space (Firefox's Applications link).
		{" ", "%20", true},
		{"trailing ", "trailing%20", true},
		{"trailing.", "trailing%2E", true},
		{"a<b>c:d", "a%3Cb%3Ec%3Ad", true},
		{"pipe|name", "pipe%7Cname", true},
		{"quo\"te", "quo%22te", true},
		{"back\\slash", "back%5Cslash", true},
		{"CON", "CON_", true},
		{"nul.txt", "nul.txt_", true},
		{"com1", "com1_", true},
		{"a b c", "a b c", false}, // internal spaces are fine
		{"dir/ /file", "dir/%20/file", true},
	}

	for _, tc := range cases {
		got, changed := sanitizePathWindows(tc.in)
		if got != tc.want || changed != tc.changed {
			t.Errorf("sanitizePathWindows(%q) = (%q, %v), want (%q, %v)",
				tc.in, got, changed, tc.want, tc.changed)
		}
	}
}
