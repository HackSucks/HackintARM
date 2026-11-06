package captureprovenance

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/nativeevidence"
)

func referenceFixture(t *testing.T) (fstest.MapFS, map[string]string) {
	t.Helper()
	source := fixture()
	recorded, err := Inventory(source)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for name, value := range source {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(value.Data); e != nil {
			t.Fatal(e)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	source["original.zip"] = &fstest.MapFile{Data: buf.Bytes()}
	id := nativeevidence.SourceSetDigest(recorded)
	catalog := nativeevidence.RetainedCatalog{Schema: 1, Records: []nativeevidence.RetainedRecord{{Path: "capture.json", SHA256: nativeevidence.Digest([]byte("original")), SourceSet: id}}, Archives: map[string]nativeevidence.OriginalArchive{id: {Path: "original.zip", SHA256: nativeevidence.Digest(buf.Bytes()), Sources: recorded}}}
	b, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	source[retainedCatalog] = &fstest.MapFile{Data: b}
	return source, recorded
}

func TestReferenceKeepsOriginalHarnessAfterChanges(t *testing.T) {
	source, recorded := referenceFixture(t)
	name := "internal/testutil/cirunner/command.go"
	before := append([]byte(nil), source[name].Data...)
	source[name] = &fstest.MapFile{Data: []byte("updated runner")}
	if err := Verify(source, recorded); err == nil {
		t.Fatal("fresh source validation weakened")
	}
	if err := VerifyReference(source, recorded); err != nil {
		t.Fatal("historical observation became stale", err)
	}
	if err := VerifyReference(source, recorded, name); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReference(source, recorded, "missing"); err == nil {
		t.Fatal("missing required original accepted")
	}
	original, err := Reference(source, recorded)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadSource(original, recorded, name)
	if err != nil || !bytes.Equal(b, before) {
		t.Fatal("original bytes substituted", err)
	}
	if _, err = ReadSource(original, recorded, "missing"); err == nil {
		t.Fatal("missing source substituted")
	}
	bad := map[string]string{name: nativeevidence.Digest(nil)}
	if _, err = ReadSource(original, bad, name); err == nil {
		t.Fatal("wrong source digest accepted")
	}
}

func TestReferenceRequiresCatalogAndCurrentUnknownSources(t *testing.T) {
	source, recorded := referenceFixture(t)
	current, err := Inventory(source)
	if err != nil {
		t.Fatal(err)
	}
	current["new native probe"] = nativeevidence.Digest([]byte("current C"))
	reference, err := Reference(source, current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fs.ReadFile(reference, "original.zip"); err != nil {
		t.Fatal("unknown current capture not checked against checkout", err)
	}
	current[implementation[0]] = nativeevidence.Digest(nil)
	if _, err = Reference(source, current); err == nil {
		t.Fatal("unknown stale source set accepted")
	}
	if err = VerifyReference(source, current); err == nil {
		t.Fatal("stale reference accepted")
	}
	source["original.zip"].Data = []byte("corrupt")
	if _, err = Reference(source, recorded); err == nil {
		t.Fatal("corrupt original archive accepted")
	}
	delete(source, retainedCatalog)
	if _, err = Reference(source, recorded); err == nil {
		t.Fatal("missing catalog accepted")
	}
	if err = VerifyReference(source, recorded); err == nil {
		t.Fatal("missing original catalog accepted")
	}
}
