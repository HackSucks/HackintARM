//go:build native_quarantine_oracle

package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"
	"unsafe"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/quarantineoracle"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

func TestQuarantineFileNativeOracle(t *testing.T) {
	path := os.Getenv("APFS_QUARANTINE_ORACLE")
	if path == "" {
		t.Fatal("native oracle path required")
	}

	process, err := CaptureQuarantineProcess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range []uint32{0, 1, 2, 4, 0x40, 0x200} {
		for _, protected := range []bool{false, true} {
			t.Run(fmt.Sprintf("flags-%x/protected-%t", flags, protected), func(t *testing.T) {
				ours, reference := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
				if protected {
					for _, f := range []*os.File{ours, reference} {
						if err := unix.Fchflags(int(f.Fd()), unix.UF_IMMUTABLE); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = unix.Chflags(f.Name(), 0) })
					}
				}
				q := &appledouble.Quarantine{Flags: flags, Timestamp: 0x1020304, Agent: "Test\\Agent;raw", Identifier: "native-comparison"}
				envelope, err := q.MarshalBinaryWithProfile(process.Profile)
				if err != nil {
					t.Fatal(err)
				}
				start := uint32(time.Now().Unix())
				code := quarantineoracle.Apply(int32(reference.Fd()), unsafe.SliceData(envelope), uint64(len(envelope)))
				got := ApplyQuarantineFile(context.Background(), ours, q, *process)
				end := uint32(time.Now().Unix())
				if code == 0 && got != nil || code > 0 && !errors.Is(got, syscall.Errno(code)) || code < 0 && got == nil {
					t.Fatalf("native=%d Go=%v", code, got)
				}
				a, ap, ae := ReadXattr(ours, "com.apple.quarantine", 4096)
				b, bp, be := ReadXattr(reference, "com.apple.quarantine", 4096)
				if ae != nil || be != nil || ap != bp {
					t.Fatalf("readback native=%t Go=%t errors=%v/%v", bp, ap, be, ae)
				}
				if !bytes.Equal(a, b) {
					am, ae := appledouble.ParseQuarantineXattrWithProfile(a, process.Profile)
					bm, be := appledouble.ParseQuarantineXattrWithProfile(b, process.Profile)
					if ae != nil || be != nil || am.Timestamp < start || am.Timestamp > end || bm.Timestamp < start || bm.Timestamp > end {
						t.Fatal("native output differs outside operation time")
					}
					am.Timestamp, bm.Timestamp = 0, 0
					if !reflect.DeepEqual(am, bm) {
						t.Fatal("native fields differ")
					}
				}
			})
		}
	}
	ours, reference := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
	code := quarantineoracle.Apply(int32(reference.Fd()), nil, 0)
	err = ApplyQuarantineFile(context.Background(), ours, nil, *process)
	if code == 0 && err != nil || code > 0 && !errors.Is(err, syscall.Errno(code)) || code < 0 && err == nil {
		t.Fatalf("clear native=%d Go=%v", code, err)
	}
}
