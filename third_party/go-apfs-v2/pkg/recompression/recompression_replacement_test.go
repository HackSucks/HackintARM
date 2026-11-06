package recompression

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// Replacement detaches one pathname from a logical inode before recompression.
// These are real host filesystem operations on each producer, including hosts
// whose materialized aliases are separate copies of the same foreign inode.
func TestCarrierReplacementRecompressionComposition(t *testing.T) {
	for _, count := range []int{2, 3} {
		for _, linked := range []bool{false, true} {
			for _, outcome := range []string{"recompress", "admission-denied", "cancel-publication", "stale-generation", "failure-after-rename", "cancel-after-rename", "cancel-after-publication"} {
				t.Run(fmt.Sprintf("names-%d/linked-%t/%s", count, linked, outcome), func(t *testing.T) {
					s, payload, _, initial, options := carrierRecompressionFixture(t)
					first, err := RecompressRecord(t.Context(), s, "file", 1, options)
					if err != nil || !first.Published || *first.Record.Darwin.Flags&hostdata.UFCompressed == 0 {
						t.Fatal(first, err)
					}
					original, err := os.ReadFile(filepath.Join(payload, "file"))
					if err != nil {
						t.Fatal(err)
					}
					initial = first.Record
					initial.LinkGroup = "original-inode"
					records := []metatransport.Record{initial}
					for i := 1; i < count; i++ {
						alias := initial
						alias.Original, alias.Materialized = fmt.Sprintf("alias-%d", i), fmt.Sprintf("alias-%d", i)
						if linked {
							err = os.Link(filepath.Join(payload, "file"), filepath.Join(payload, alias.Materialized))
						} else {
							err = os.WriteFile(filepath.Join(payload, alias.Materialized), original, 0600)
						}
						if err != nil {
							t.Fatal(err)
						}
						records = append(records, alias)
					}
					if err = s.Commit(t.Context(), metatransport.Manifest{Version: 1, Generation: 2, Records: records}, 2); err != nil {
						t.Fatal(err)
					}
					before, err := s.Load(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					root, err := os.OpenRoot(payload)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if e := root.Close(); e != nil {
							t.Error(e)
						}
					}()
					source, err := root.Open("file")
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if e := source.Close(); e != nil {
							t.Error(e)
						}
					}()
					oldInfo, err := source.Stat()
					if err != nil {
						t.Fatal(err)
					}
					stage, err := hostdata.PrepareReplacementAtContext(t.Context(), source, root, ".")
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if e := stage.Close(); e != nil {
							t.Error(e)
						}
					}()
					replacement := bytes.Repeat([]byte("replacement signed bytes"), 3072)
					if err = stage.File.Truncate(0); err != nil {
						t.Fatal(err)
					}
					if _, err = stage.File.WriteAt(replacement, 0); err != nil {
						t.Fatal(err)
					}
					if err = stage.RestoreMetadataContext(t.Context()); err != nil {
						t.Fatal(err)
					}
					if err = stage.File.Sync(); err != nil {
						t.Fatal(err)
					}
					if err = stage.File.Close(); err != nil {
						t.Fatal(err)
					}

					next, err := s.Load(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					target := next.Records[0]
					target.LinkGroup, target.AppleDouble = "", nil
					ref, flags := digest(replacement), *target.Darwin.Flags&^hostdata.UFCompressed
					target.Payload, target.Darwin.Flags = &ref, &flags
					attrs, err := s.ReadRecordAttributes(t.Context(), target, 1<<20)
					if err != nil {
						t.Fatal(err)
					}
					delete(attrs, hostdata.DecmpfsName)
					delete(attrs, hostdata.ResourceForkName)
					target.Attributes, err = s.StoreAttributes(t.Context(), attrs)
					if err != nil {
						t.Fatal(err)
					}
					next.Records[0] = target
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if outcome == "cancel-publication" {
						cancel()
					}
					expected := uint64(3)
					if outcome == "stale-generation" {
						expected--
					}
					boundaryFailure := errors.New("failure after payload rename")
					called := false
					published, err := s.Publish(ctx, next, expected, func() error {
						called = true
						if e := s.CheckPayload(t.Context(), "file", source); e != nil {
							return e
						}
						if e := metatransport.VerifyHeldPayload(t.Context(), source, *initial.Payload); e != nil {
							return e
						}
						if e := root.Rename(stage.Path, "file"); e != nil {
							return e
						}
						if outcome == "failure-after-rename" {
							return boundaryFailure
						}
						if outcome == "cancel-after-rename" {
							cancel()
							return ctx.Err()
						}
						return nil
					})
					if outcome == "cancel-publication" || outcome == "stale-generation" {
						want := metatransport.ErrConflict
						if outcome == "cancel-publication" {
							want = context.Canceled
						}
						if published || called || !errors.Is(err, want) {
							t.Fatal(published, called, err)
						}
						got, e := s.Load(t.Context())
						if e != nil || !reflect.DeepEqual(got, before) {
							t.Fatal("preflight changed manifest", got, e)
						}
						data, e := root.ReadFile("file")
						if e != nil || !bytes.Equal(data, original) {
							t.Fatal("preflight changed target", e)
						}
						return
					}
					if outcome == "failure-after-rename" || outcome == "cancel-after-rename" {
						want := boundaryFailure
						if outcome == "cancel-after-rename" {
							want = context.Canceled
						}
						if published || !called || !errors.Is(err, want) {
							t.Fatal("partial transition", published, called, err)
						}
						got, e := s.Load(t.Context())
						if e != nil || !reflect.DeepEqual(got, before) {
							t.Fatal("failed callback published manifest", got, e)
						}
						data, e := root.ReadFile("file")
						if e != nil || !bytes.Equal(data, replacement) {
							t.Fatal("partial payload effect lost", e)
						}
						if e = s.VerifyPayload(t.Context(), got.Records[0]); !errors.Is(e, metatransport.ErrCorrupt) {
							t.Fatal("stale compressed baseline accepted", e)
						}
						result, e := RecompressRecord(t.Context(), s, "file", 3, options)
						if !errors.Is(e, metatransport.ErrConflict) || result.Published || result.Operation.Accepted {
							t.Fatal("partial publication reactivated old storage", result, e)
						}
						for _, alias := range got.Records[1:] {
							if e = s.VerifyPayload(t.Context(), alias); e != nil {
								t.Fatal("unaffected alias", alias.Original, e)
							}
							info, e := root.Stat(alias.Materialized)
							if e != nil || linked && !os.SameFile(oldInfo, info) {
								t.Fatal("unaffected alias identity", e)
							}
						}
						if e = stage.Close(); e != nil {
							t.Fatal(e)
						}
						entries, e := os.ReadDir(payload)
						if e != nil || len(entries) != count {
							t.Fatal("partial transition staging leaked", entries, e)
						}
						return
					}
					if err != nil || !published || !called {
						t.Fatal(published, called, err)
					}
					if err = stage.Close(); err != nil {
						t.Fatal(err)
					}
					newInfo, err := root.Stat("file")
					if err != nil || os.SameFile(oldInfo, newInfo) {
						t.Fatal("replacement retained original inode", err)
					}
					if outcome == "admission-denied" {
						options.Authority = &Authority{UID: 502, Groups: []uint32{20}}
					}
					recompressionContext := t.Context()
					if outcome == "cancel-after-publication" {
						cancel()
						recompressionContext = ctx
					}
					result, err := RecompressRecord(recompressionContext, s, "file", 4, options)
					if outcome == "admission-denied" {
						if err == nil || result.Published || result.Operation.Accepted {
							t.Fatal(result, err)
						}
					} else if outcome == "cancel-after-publication" {
						if !errors.Is(err, context.Canceled) || result.Published || result.Operation.Accepted {
							t.Fatal("canceled recompression changed committed baseline", result, err)
						}
					} else if err != nil || !result.Published || !result.Operation.Accepted {
						t.Fatal(result, err)
					}
					after, err := s.Load(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if after.Generation != 4 && outcome != "recompress" || after.Generation != 5 && outcome == "recompress" {
						t.Fatal("generation", after.Generation)
					}
					for i, record := range after.Records {
						if err = s.VerifyPayload(t.Context(), record); err != nil {
							t.Fatal(record.Original, err)
						}
						data, e := root.ReadFile(record.Materialized)
						if e != nil {
							t.Fatal(e)
						}
						if i == 0 {
							if !bytes.Equal(data, replacement) || record.LinkGroup != "" || *record.Payload != ref {
								t.Fatal("replacement association", record)
							}
							if outcome != "recompress" && !reflect.DeepEqual(record, target) {
								t.Fatal("failed admission lost uncompressed signed baseline", record)
							}
						} else {
							if !bytes.Equal(data, original) || !reflect.DeepEqual(record, before.Records[i]) {
								t.Fatal("unaffected alias changed", record)
							}
							info, e := root.Stat(record.Materialized)
							if e != nil || os.SameFile(newInfo, info) || linked && !os.SameFile(oldInfo, info) {
								t.Fatal("alias identity", e)
							}
						}
					}
					checkRecompressionCleanup(t, options.TemporaryDirectory)
					entries, err := os.ReadDir(payload)
					if err != nil || len(entries) != count {
						t.Fatal("private replacement staging leaked", entries, err)
					}
				})
			}
		}
	}
}
