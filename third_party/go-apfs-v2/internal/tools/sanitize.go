// Filename sanitization for representing source names on the host
// file system. The Windows rules live here (compiled on every platform so
// they are unit-testable); the build-tagged files decide when to apply them.
package tools

import "strings"

// windowsReservedNames are device names that cannot be used as a path
// component on Windows (case-insensitive, with or without an extension).
var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// sanitizePathWindows makes each slash-separated component of rel storable on
// Windows: reserved characters and control bytes are percent-encoded, trailing
// spaces/dots are encoded (Windows silently strips them), and reserved device
// names are suffixed. Returns the sanitized path (still slash-separated) and
// whether anything changed.
func sanitizePathWindows(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	changed := false
	for i, part := range parts {
		clean := sanitizeComponentWindows(part)
		if clean != part {
			changed = true
		}
		parts[i] = clean
	}
	return strings.Join(parts, "/"), changed
}

func sanitizeComponentWindows(name string) string {
	if name == "" || name == "." || name == ".." {
		return name
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20, r == '<', r == '>', r == ':', r == '"', r == '|', r == '?', r == '*', r == '\\':
			b.WriteString(percentEncode(r))
		default:
			b.WriteRune(r)
		}
	}
	result := b.String()

	// Windows strips trailing spaces and dots; encode the last character when
	// it would otherwise be lost so the name survives.
	if last := result[len(result)-1]; last == ' ' || last == '.' {
		result = result[:len(result)-1] + percentEncode(rune(last))
	}

	// Reserved device names (ignoring any extension) get a suffix.
	stem := result
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	if windowsReservedNames[strings.ToUpper(stem)] {
		result += "_"
	}

	return result
}

func percentEncode(r rune) string {
	const hex = "0123456789ABCDEF"
	if r < 0x80 {
		return string([]byte{'%', hex[byte(r)>>4], hex[byte(r)&0xf]})
	}
	var b strings.Builder
	for _, c := range []byte(string(r)) {
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}
