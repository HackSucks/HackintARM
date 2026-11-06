package xattrintent

import "testing"

func TestXattrIntentPolicy(t *testing.T) {
	for _, v := range []struct {
		name string
		want [5]bool
	}{
		{"unknown", [5]bool{true, true, true, false, true}},
		{"unknown#P", [5]bool{true, true, false, false, true}},
		{"unknown#C", [5]bool{true, false, true, false, true}},
		{"unknown#N", [5]bool{false, false, false, false, false}},
		{"unknown#S", [5]bool{true, true, true, true, true}},
		{"unknown#B", [5]bool{false, false, false, false, true}},
		{"unknown#X", [5]bool{false, true, false, false, true}},
		{"unknown#SX", [5]bool{false, true, false, true, true}},
		{"unknown#PCNSBXpcnsbx?", [5]bool{true, true, true, false, true}},
		{"com.apple.quarantine", [5]bool{true, false, false, true, true}},
		{"com.apple.ResourceFork", [5]bool{true, false, false, true, true}},
		{"com.apple.FinderInfo", [5]bool{true, false, false, true, true}},
		{"com.apple.TextEncoding", [5]bool{true, false, true, true, true}},
		{"com.apple.root.installed", [5]bool{true, false, false, false, true}},
		{"com.apple.metadata:kMDItemCollaborationIdentifier", [5]bool{false, false, false, false, true}},
		{"com.apple.metadata:kMDItemIsShared", [5]bool{false, false, false, false, true}},
		{"com.apple.metadata:kMDItemSharedItemCurrentUserRole", [5]bool{false, false, false, false, true}},
		{"com.apple.metadata:kMDItemOwnerName", [5]bool{false, false, false, false, true}},
		{"com.apple.metadata:kMDItemFavoriteRank", [5]bool{false, false, false, false, true}},
		{"com.apple.metadata:custom", [5]bool{true, true, false, true, true}},
		{"com.apple.metadata:custom#", [5]bool{true, true, true, false, true}},
		{"unknown#N#S", [5]bool{true, true, true, true, true}},
		{"unknown#S\x00N", [5]bool{true, true, true, true, true}},
	} {
		t.Run(v.name, func(t *testing.T) {
			for i, want := range v.want {
				for _, sandboxed := range []bool{false, true} {
					if got := PreserveXattrForIntent(v.name, uint32(i+1), sandboxed); got != want {
						t.Fatalf("intent%d sandbox%t got%t want%t", i+1, sandboxed, got, want)
					}
				}
			}
		})
	}
	for _, intent := range []uint32{0, 1, 2, 3, 4, 5, 99, 0xffffffff} {
		if PreserveXattrForIntent("x#N", intent, false) {
			t.Fatal(intent)
		}
		if !PreserveXattrForIntent("x#NSn", intent, false) {
			t.Fatal(intent)
		}
		if PreserveXattrForIntent("com.apple.security.custom", intent, true) {
			t.Fatal(intent)
		}
		if !PreserveXattrForIntent("com.apple.security.custom", intent, false) {
			t.Fatal(intent)
		}
	}
}
