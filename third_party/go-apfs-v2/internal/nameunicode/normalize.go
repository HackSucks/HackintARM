// Package nameunicode implements filesystem-pinned Unicode normalization.
// It does not decide whether a macOS version admits a pathname component.
package nameunicode

import "unicode/utf8"

// APFS returns the canonical comparison/hash scalars. Canonical ordering must
// precede folding (notably U+0345), and full folding may expand one scalar.
func APFS(s string, fold bool) []rune {
	out := normalize([]rune(s), apfsDecompose, apfsClass)
	if !fold {
		return out
	}
	var folded []rune
	for _, r := range out {
		if f, ok := apfsFold[r]; ok {
			folded = append(folded, []rune(f)...)
		} else {
			folded = append(folded, r)
		}
	}
	return normalize(folded, apfsDecompose, apfsClass)
}

// HFS returns the catalog spelling: frozen BMP canonical decomposition with
// HFS exclusions and canonical ordering. Supplementary scalars stay intact.
func HFS(s string) string { return string(normalize(hfsScalars(s), hfsDecompose, hfsClass)) }

func normalize(input []rune, decomposition map[rune]string, class map[rune]uint8) []rune {
	out := make([]rune, 0, len(input))
	var add func(rune)
	add = func(r rune) {
		if r >= 0xac00 && r <= 0xd7a3 {
			n := r - 0xac00
			add(0x1100 + n/588)
			add(0x1161 + n%588/28)
			if n%28 != 0 {
				add(0x11a7 + n%28)
			}
			return
		}
		if expanded, ok := decomposition[r]; ok {
			for _, r := range expanded {
				add(r)
			}
			return
		}
		out = append(out, r)
		// Stable canonical ordering stops at a starter or equal combining class.
		for i := len(out) - 1; class[r] != 0 && i > 0 && class[out[i-1]] > class[r]; i-- {
			out[i], out[i-1] = out[i-1], out[i]
		}
	}
	for _, r := range input {
		add(r)
	}
	return out
}

// hfsScalars follows XNU utf8_decodestr with UTF_ESCAPE_ILLEGAL. Invalid
// bytes and the two rejected BMP noncharacters become literal percent escapes;
// they must never alias U+FFFD through Go's replacement-rune decoding.
func hfsScalars(s string) []rune {
	const digits = "0123456789ABCDEF"
	var out []rune
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		if (r == utf8.RuneError && n == 1) || r == 0xfffe || r == 0xffff {
			out = append(out, '%', rune(digits[s[0]>>4]), rune(digits[s[0]&15]))
			s = s[1:]
			continue
		}
		out = append(out, r)
		s = s[n:]
	}
	return out
}
