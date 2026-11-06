package hfsplus

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
)

// Native fdopendir needs the empty folder-thread key even when the folder
// contains an all-ignorable name. CompareExtendedCatalogKeys in the retained
// Apple hfs_catalog.c explicitly orders empty keys before applying case folding.
func TestCatalogThreadBeforeIgnorableNames(t *testing.T) {
	for _, name := range []string{"\u200c", "\u200d", "\u200c\u200d", "a"} {
		t.Run(fmt.Sprintf("%x", name), func(t *testing.T) {
			thread, file := encodeCatalogKey(42, ""), encodeCatalogKey(42, name)
			if compareCatalogKeysFolded(thread, file) >= 0 || compareCatalogKeysFolded(file, thread) <= 0 {
				t.Fatal("thread key must remain distinct and sort before a nonempty filename")
			}
		})
	}
	if compareCatalogKeysFolded(encodeCatalogKey(42, ""), encodeCatalogKey(42, "")) != 0 {
		t.Fatal("identical thread keys differ")
	}
	if compareCatalogKeysFolded(encodeCatalogKey(42, "\u200c"), encodeCatalogKey(42, "\u200d")) != 0 {
		t.Fatal("nonempty ignorable names lost native equivalence")
	}
	if compareCatalogKeysFolded(encodeCatalogKey(43, ""), encodeCatalogKey(42, "a")) <= 0 {
		t.Fatal("parent identity must precede the empty-key rule")
	}
}

func TestCatalogThreadRecordOrder(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		t.Run(fmt.Sprint(sensitive), func(t *testing.T) {
			b := &builder{nextCNID: 16, caseInsensitive: !sensitive}
			root := b.flatten(&Entry{Mode: os.ModeDir, Children: []*Entry{
				{Name: "directory", Mode: os.ModeDir, Children: []*Entry{{Name: "\u200d"}}},
			}}, "ThreadControl")
			records := b.catalogRecords(root)
			// Every directory's empty thread key must precede its children. Checking
			// the encoded records also catches unstable-sort equal-key regressions.
			seenThreads := map[CatalogNodeID]bool{}
			var previous []byte
			cmp := compareCatalogKeysFolded
			if sensitive {
				cmp = compareCatalogKeys
			}
			for _, record := range records {
				parent, name := catalogKeyFields(record.key)
				if previous != nil && cmp(previous, record.key) >= 0 {
					t.Fatal("duplicate or unordered encoded catalog key")
				}
				previous = record.key
				kind := binary.BigEndian.Uint16(record.payload)
				if len(name) == 0 {
					if kind != uint16(HFSPlusFolderThreadRecord) && kind != uint16(HFSPlusFileThreadRecord) {
						t.Fatal("empty name is not a thread")
					}
					seenThreads[parent] = true
				} else if parent != HFSRootParentID && !seenThreads[parent] {
					t.Fatal("child record precedes parent folder thread")
				}
			}
		})
	}
}
