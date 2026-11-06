package recompression

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func TestCarrierInPlaceEditedAliases(t *testing.T) {
	for _, count := range []int{2, 3} {
		for _, linked := range []bool{false, true} {
			t.Run(fmt.Sprintf("names-%d/linked-%t", count, linked), func(t *testing.T) {
				store, payload, _, _, options := carrierRecompressionFixture(t)
				first, err := RecompressRecord(t.Context(), store, "file", 1, options)
				if err != nil || !first.Published || *first.Record.Darwin.Flags&hostdata.UFCompressed == 0 {
					t.Fatal(first, err)
				}
				original, err := os.ReadFile(filepath.Join(payload, "file"))
				if err != nil {
					t.Fatal(err)
				}
				selected := first.Record
				selected.LinkGroup = "same-logical-inode"
				records := []metatransport.Record{selected}
				identities := make([]os.FileInfo, count)
				identities[0], err = os.Stat(filepath.Join(payload, "file"))
				if err != nil {
					t.Fatal(err)
				}
				for i := 1; i < count; i++ {
					alias := selected
					alias.Original = fmt.Sprintf("alias-%d", i)
					alias.Materialized = alias.Original
					if linked {
						err = os.Link(filepath.Join(payload, "file"), filepath.Join(payload, alias.Materialized))
					} else {
						err = os.WriteFile(filepath.Join(payload, alias.Materialized), original, 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					identities[i], err = os.Stat(filepath.Join(payload, alias.Materialized))
					if err != nil {
						t.Fatal(err)
					}
					records = append(records, alias)
				}
				if err = store.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 2, Records: records}, 2); err != nil {
					t.Fatal(err)
				}
				edited := bytes.Repeat([]byte("edited logical inode"), 5000)
				if err = os.WriteFile(filepath.Join(payload, "file"), edited, 0600); err != nil {
					t.Fatal(err)
				}
				options.AllowChangedPayload = true
				result, err := RecompressRecord(t.Context(), store, "file", 3, options)
				if err != nil || !result.Published || !result.Operation.Accepted || result.Generation != 4 {
					t.Fatal(result, err)
				}
				manifest, err := store.Load(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if manifest.Generation != 4 || len(manifest.Records) != count {
					t.Fatal(manifest)
				}
				baseline := digest(edited)
				for i, record := range manifest.Records {
					if record.LinkGroup != selected.LinkGroup || *record.Payload != baseline || *record.Darwin.Flags&hostdata.UFCompressed == 0 {
						t.Fatal("logical alias state", record)
					}
					if !reflect.DeepEqual(recompressionAliasState(record), recompressionAliasState(manifest.Records[0])) {
						t.Fatal("logical inode metadata diverged", record)
					}
					if err = store.VerifyPayload(t.Context(), record); err != nil {
						t.Fatal(err)
					}
					data, e := os.ReadFile(filepath.Join(payload, record.Materialized))
					if e != nil || !bytes.Equal(data, edited) {
						t.Fatal("alias payload not updated", record.Original, e)
					}
					current, e := os.Stat(filepath.Join(payload, record.Materialized))
					if e != nil || !os.SameFile(current, identities[i]) {
						t.Fatal("in-place operation replaced alias inode", e)
					}
					values, e := store.BorrowRecordAttributes(t.Context(), record)
					if e != nil {
						t.Fatal(e)
					}
					if e = validateRecompressionStorage(t.Context(), values, baseline); e != nil {
						t.Fatal("new compressed storage did not match edited inode", e)
					}
				}
				checkRecompressionCleanup(t, options.TemporaryDirectory)
			})
		}
	}
}
