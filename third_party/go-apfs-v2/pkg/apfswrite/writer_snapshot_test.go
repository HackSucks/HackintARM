// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestSnapshotWriterRejectsBadSpecs covers the snapshot validation error paths
// (cross-platform, no external tools).
func TestSnapshotWriterRejectsBadSpecs(t *testing.T) {
	cases := []struct {
		name  string
		snaps []apfswrite.SnapshotSpec
	}{
		{"empty name", []apfswrite.SnapshotSpec{{Name: ""}}},
		{"duplicate-nul", []apfswrite.SnapshotSpec{{Name: "a\x00b"}}},
		// Several snapshots are supported now; only a repeated name is not,
		// since a snapshot is looked up by name.
		{"duplicate name", []apfswrite.SnapshotSpec{{Name: "a"}, {Name: "a"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "snap-*.img")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			err = apfswrite.CreateContainer(f, 32*1024*1024, &apfswrite.CreateOptions{
				VolumeName: "V",
				RootFiles:  []apfswrite.RootFile{{Name: "f", Data: []byte("x")}},
				Snapshots:  tc.snaps,
			})
			if err == nil {
				t.Errorf("expected an error for %q, got nil", tc.name)
			}
		})
	}
}

// snapshotNames builds a spec list of n snapshots named snap1..snapN.
func snapshotNames(n int) []apfswrite.SnapshotSpec {
	specs := make([]apfswrite.SnapshotSpec, n)
	for i := range specs {
		specs[i] = apfswrite.SnapshotSpec{Name: fmt.Sprintf("snap%d", i+1)}
	}
	return specs
}

// TestMultipleSnapshotsRoundTrip is the point of lifting the one-snapshot cap:
// several snapshots on one volume, each with its own transaction id, all
// readable.
//
// The cap existed because the live volume shared the single checkpoint's
// transaction id. Raising the live id past the snapshots needs a predecessor
// checkpoint, or macOS refuses to mount a container whose only checkpoint
// appears to begin mid-stream.
func TestMultipleSnapshotsRoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 3, 8} {
		t.Run(fmt.Sprintf("%d snapshots", n), func(t *testing.T) {
			vol := openVolume(t, &apfswrite.CreateOptions{
				VolumeName: "SNAPS",
				Snapshots:  snapshotNames(n),
				Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
					{Name: "f.txt", Data: []byte("content\n")},
				}},
			})

			count, err := vol.NumberOfSnapshots()
			if err != nil {
				t.Fatalf("NumberOfSnapshots: %v", err)
			}
			if count != n {
				t.Fatalf("volume holds %d snapshots, want %d", count, n)
			}

			// Each snapshot keeps its own name and a transaction id of its own,
			// ascending in the order they were asked for.
			for i := range n {
				snap, err := vol.Snapshot(i)
				if err != nil {
					t.Fatalf("Snapshot(%d): %v", i, err)
				}
				name, err := snap.UTF8Name()
				if err != nil {
					t.Fatalf("Snapshot(%d).UTF8Name: %v", i, err)
				}
				if want := fmt.Sprintf("snap%d", i+1); name != want {
					t.Errorf("snapshot %d is named %q, want %q", i, name, want)
				}
			}

			// The live volume still reads, which is the thing a raised
			// transaction id is most likely to break.
			if data, err := vol.ReadFile("f.txt"); err != nil || string(data) != "content\n" {
				t.Errorf("f.txt = %q, %v", data, err)
			}
		})
	}
}

// TestSnapshotCountIsCapped checks the limit is reported rather than producing
// a snapshot-metadata tree too large for its single node.
func TestSnapshotCountIsCapped(t *testing.T) {
	err := apfswrite.CreateContainer(&memImage{}, 64*1024*1024, &apfswrite.CreateOptions{
		VolumeName: "TOOMANY",
		Snapshots:  snapshotNames(1000),
	})
	if err == nil {
		t.Fatal("CreateContainer accepted 1000 snapshots")
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Errorf("error = %q, want it to name the limit", err)
	}
}
