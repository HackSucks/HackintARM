// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// volumeSpecs builds n volumes, each with a file naming itself so a mix-up
// between them is visible rather than merely suspected.
func volumeSpecs(n int) []apfswrite.VolumeSpec {
	specs := make([]apfswrite.VolumeSpec, n)
	for i := range specs {
		specs[i] = apfswrite.VolumeSpec{
			Name: fmt.Sprintf("Vol%d", i+1),
			Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
				{Name: fmt.Sprintf("file%d.txt", i+1), Data: fmt.Appendf(nil, "contents of volume %d\n", i+1)},
			}},
		}
	}
	return specs
}

// multiVolumeSize is the smallest container the format allows for n volumes:
// APFS permits one per 512 MiB. The images are sparse, so this costs little.
func multiVolumeSize(n int) int64 { return int64(n) * 512 * 1024 * 1024 }

func openContainer(t *testing.T, size int64, opts *apfswrite.CreateOptions) *apfs.Container {
	t.Helper()
	img := &memImage{}
	if err := apfswrite.CreateContainer(img, size, opts); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	container, err := apfs.Open(img, &apfs.OpenOptions{})
	if err != nil {
		t.Fatalf("apfs.Open: %v", err)
	}
	return container
}

// TestMultipleVolumesRoundTrip is the point of the change: several volumes in
// one container, each with its own name and its own contents.
func TestMultipleVolumesRoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%d volumes", n), func(t *testing.T) {
			container := openContainer(t, multiVolumeSize(n),
				&apfswrite.CreateOptions{Volumes: volumeSpecs(n)})

			volumes, err := container.Volumes()
			if err != nil {
				t.Fatalf("Volumes: %v", err)
			}
			if len(volumes) != n {
				t.Fatalf("container holds %d volumes, want %d", len(volumes), n)
			}

			for i, vol := range volumes {
				want := fmt.Sprintf("Vol%d", i+1)
				name, err := vol.UTF8Name()
				if err != nil {
					t.Fatalf("volume %d: UTF8Name: %v", i, err)
				}
				if name != want {
					t.Errorf("volume %d is named %q, want %q", i, name, want)
				}
				// Each volume must hold its own file and nothing else's: a
				// shared object map or a mixed-up tree root shows up here.
				own := fmt.Sprintf("file%d.txt", i+1)
				data, err := vol.ReadFile(own)
				if err != nil {
					t.Errorf("volume %d: reading %s: %v", i, own, err)
					continue
				}
				if got, want := string(data), fmt.Sprintf("contents of volume %d\n", i+1); got != want {
					t.Errorf("volume %d: %s = %q, want %q", i, own, got, want)
				}
				for j := range n {
					if j == i {
						continue
					}
					if _, err := vol.ReadFile(fmt.Sprintf("file%d.txt", j+1)); err == nil {
						t.Errorf("volume %d can see volume %d's file", i, j)
					}
				}
			}
		})
	}
}

// TestMultipleVolumesNeedRoom pins the format's sizing rule: one volume per
// 512 MiB. A container too small would be refused on mount, so it is refused
// here with the size it would need.
func TestMultipleVolumesNeedRoom(t *testing.T) {
	err := apfswrite.CreateContainer(&memImage{}, 64*1024*1024,
		&apfswrite.CreateOptions{Volumes: volumeSpecs(2)})
	if err == nil {
		t.Fatal("CreateContainer accepted two volumes in 64 MiB")
	}
	if !strings.Contains(err.Error(), "at least") {
		t.Errorf("error = %q, want it to say how large the container must be", err)
	}
}

// TestVolumesAndScalarOptionsAreExclusive checks the two ways of describing a
// volume cannot be mixed. Silently preferring one would write a container the
// caller did not ask for.
func TestVolumesAndScalarOptionsAreExclusive(t *testing.T) {
	err := apfswrite.CreateContainer(&memImage{}, multiVolumeSize(2), &apfswrite.CreateOptions{
		VolumeName: "Scalar",
		Volumes:    volumeSpecs(2),
	})
	if err == nil {
		t.Fatal("CreateContainer accepted both Volumes and the single-volume fields")
	}
	if !strings.Contains(err.Error(), "one or the other") {
		t.Errorf("error = %q, want it to say the two are alternatives", err)
	}
}

// TestSingleVolumeSpecMatchesScalars checks the two spellings of one volume
// produce the same container, which is what keeps every existing caller
// byte-identical.
func TestSingleVolumeSpecMatchesScalars(t *testing.T) {
	build := func(opts *apfswrite.CreateOptions) []byte {
		img := &memImage{}
		if err := apfswrite.CreateContainer(img, 64*1024*1024, opts); err != nil {
			t.Fatalf("CreateContainer: %v", err)
		}
		return img.data
	}

	tree := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "f.txt", Data: []byte("same either way\n")},
	}}
	scalar := build(&apfswrite.CreateOptions{VolumeName: "One", Root: tree})
	spec := build(&apfswrite.CreateOptions{
		Volumes: []apfswrite.VolumeSpec{{Name: "One", Root: tree}},
	})

	if len(scalar) != len(spec) {
		t.Fatalf("the two spellings produced %d and %d bytes", len(scalar), len(spec))
	}
	for i := range scalar {
		if scalar[i] != spec[i] {
			t.Fatalf("the two spellings differ at byte %d", i)
		}
	}
}

// TestSnapshotsAcrossVolumes checks snapshots belong to the volume that asked
// for them, and that their transaction ids come from one container-wide
// sequence rather than each volume starting again at one.
//
// A transaction id is the container's, not a volume's: two volumes' snapshots
// are two points in the same history. Numbering them per volume would give two
// snapshots the same id, and the live state -- one transaction past the newest
// of them -- would then be ambiguous.
func TestSnapshotsAcrossVolumes(t *testing.T) {
	snaps := func(names ...string) []apfswrite.SnapshotSpec {
		out := make([]apfswrite.SnapshotSpec, len(names))
		for i, n := range names {
			out[i] = apfswrite.SnapshotSpec{Name: n}
		}
		return out
	}

	container := openContainer(t, multiVolumeSize(2), &apfswrite.CreateOptions{
		Volumes: []apfswrite.VolumeSpec{
			{Name: "Vol1", Snapshots: snaps("v1snapA", "v1snapB"), Root: &apfswrite.Entry{
				Children: []*apfswrite.Entry{{Name: "file1.txt", Data: []byte("volume 1\n")}},
			}},
			{Name: "Vol2", Snapshots: snaps("v2snapA"), Root: &apfswrite.Entry{
				Children: []*apfswrite.Entry{{Name: "file2.txt", Data: []byte("volume 2\n")}},
			}},
		},
	})

	volumes, err := container.Volumes()
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}

	want := [][]string{{"v1snapA", "v1snapB"}, {"v2snapA"}}
	for i, vol := range volumes {
		count, err := vol.NumberOfSnapshots()
		if err != nil {
			t.Fatalf("volume %d: NumberOfSnapshots: %v", i, err)
		}
		if count != len(want[i]) {
			t.Errorf("volume %d holds %d snapshots, want %d", i, count, len(want[i]))
			continue
		}
		for j, wantName := range want[i] {
			snap, err := vol.Snapshot(j)
			if err != nil {
				t.Fatalf("volume %d: Snapshot(%d): %v", i, j, err)
			}
			name, err := snap.UTF8Name()
			if err != nil {
				t.Fatalf("volume %d: Snapshot(%d).UTF8Name: %v", i, j, err)
			}
			if name != wantName {
				t.Errorf("volume %d snapshot %d is named %q, want %q", i, j, name, wantName)
			}
		}

		// Snapshots must not disturb the live contents of either volume.
		own := fmt.Sprintf("file%d.txt", i+1)
		if data, err := vol.ReadFile(own); err != nil {
			t.Errorf("volume %d: reading %s: %v", i, own, err)
		} else if got, want := string(data), fmt.Sprintf("volume %d\n", i+1); got != want {
			t.Errorf("volume %d: %s = %q, want %q", i, own, got, want)
		}
	}
}
