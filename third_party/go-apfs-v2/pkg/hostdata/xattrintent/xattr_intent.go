package xattrintent

import "strings"

// PreserveXattrForIntent applies Apple's explicit xattr property/intent policy.
// Intents are copy=1, save=2, share=3, sync=4 and backup=5. Unknown intents still
// honor NEVER_PRESERVE. A final # suffix replaces the name defaults; later lower
// case property letters clear earlier upper case letters. Sandboxed is captured
// source-process policy, not the operating system currently executing Go.
func PreserveXattrForIntent(name string, intent uint32, sandboxed bool) bool {
	name, _, _ = strings.Cut(name, "\x00")
	var properties string
	if i := strings.LastIndexByte(name, '#'); i >= 0 {
		properties = name[i+1:]
	} else {
		properties = defaultXattrProperties(name, sandboxed)
	}
	var flags uint8
	for _, c := range []byte(properties) {
		var bit uint8
		switch c {
		case 'P', 'p':
			bit = 1
		case 'C', 'c':
			bit = 2
		case 'N', 'n':
			bit = 4
		case 'S', 's':
			bit = 8
		case 'B', 'b':
			bit = 16
		case 'X', 'x':
			bit = 32
		}
		if c >= 'a' && c <= 'z' {
			flags &^= bit
		} else {
			flags |= bit
		}
	}
	switch intent {
	case 1:
		return flags&(4|16|32) == 0
	case 2:
		return flags&(2|4|16) == 0
	case 3:
		return flags&(1|4|16|32) == 0
	case 4:
		return flags&(8|4|16) == 8
	default:
		return flags&4 == 0
	}
}

func defaultXattrProperties(name string, sandboxed bool) string {
	switch name {
	case "com.apple.quarantine", "com.apple.ResourceFork", "com.apple.FinderInfo":
		return "PCS"
	case "com.apple.TextEncoding":
		return "CS"
	case "com.apple.metadata:kMDItemCollaborationIdentifier", "com.apple.metadata:kMDItemIsShared", "com.apple.metadata:kMDItemSharedItemCurrentUserRole", "com.apple.metadata:kMDItemOwnerName", "com.apple.metadata:kMDItemFavoriteRank":
		return "B"
	case "com.apple.root.installed":
		return "PC"
	}
	if strings.HasPrefix(name, "com.apple.metadata:") {
		return "PS"
	}
	if strings.HasPrefix(name, "com.apple.security.") {
		if sandboxed {
			return "N"
		}
		return "S"
	}
	return ""
}
