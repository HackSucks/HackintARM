package apfs

import (
	"slices"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/internal/nameunicode"
)

// Build the table during package initialization. Hashing only reads it, so
// concurrent first calls through either UTF entry point cannot race.
var crc32CTable = makeCRC32CTable()

func makeCRC32CTable() [256]uint32 {
	var table [256]uint32
	// APFS hashes names with CRC-32C (Castagnoli), polynomial 0x82f63b78.
	const polynomial uint32 = 0x82f63b78

	for tableIndex := uint32(0); tableIndex < 256; tableIndex++ {
		checksum := tableIndex

		for bitIterator := 0; bitIterator < 8; bitIterator++ {
			if checksum&1 != 0 {
				checksum = polynomial ^ (checksum >> 1)
			} else {
				checksum = checksum >> 1
			}
		}

		table[tableIndex] = checksum
	}

	return table
}

// CalculateNameHash calculates APFS's raw CRC-32C over canonical comparison
// scalars. Valid U+FFFD is a character, not a decoding failure. A terminating
// NUL or malformed UTF-8 ends the legacy byte-string input.
func CalculateNameHash(input []byte, fold bool) uint32 {
	end := 0
	for end < len(input) {
		r, n := utf8.DecodeRune(input[end:])
		if r == 0 || (r == utf8.RuneError && n == 1) {
			break
		}
		end += n
	}
	return hashName(nameunicode.APFS(string(input[:end]), fold))
}

// CalculateNameHashFromUTF16 hashes UTF-16 through the same canonical pipeline.
func CalculateNameHashFromUTF16(input []uint16, fold bool) uint32 {
	end := 0
	for end < len(input) && input[end] != 0 {
		end++
	}
	return hashName(nameunicode.APFS(UTF16ToString(input[:end]), fold))
}

func hashName(scalars []rune) uint32 {
	checksum := uint32(0xffffffff)
	for _, r := range scalars {
		value := uint32(r)
		for range 4 {
			checksum = crc32CTable[(checksum^value)&255] ^ (checksum >> 8)
			value >>= 8
		}
	}
	return checksum & 0x3fffff
}

// UTF16ToString converts a UTF-16 slice to a UTF-8 string
func UTF16ToString(utf16Data []uint16) string {
	runes := utf16.Decode(utf16Data)
	return string(runes)
}

// StringToUTF16 converts a UTF-8 string to a UTF-16 slice
func StringToUTF16(str string) []uint16 {
	runes := []rune(str)
	return utf16.Encode(runes)
}

// CompareNamesWithUTF8 compares canonical APFS names using full case folding
// when requested. Admission by a specific macOS version is a separate policy.
func CompareNamesWithUTF8(a, b []byte, fold bool) int {
	return slices.Compare(nameunicode.APFS(string(a), fold), nameunicode.APFS(string(b), fold))
}

// CompareNamesWithUTF16 uses the same comparison pipeline for UTF-16 names.
func CompareNamesWithUTF16(a, b []uint16, fold bool) int {
	return CompareNamesWithUTF8([]byte(UTF16ToString(a)), []byte(UTF16ToString(b)), fold)
}
