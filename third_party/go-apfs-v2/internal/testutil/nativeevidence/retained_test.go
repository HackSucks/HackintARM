package nativeevidence

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"testing"
	"testing/fstest"
)

func retainedFixture(t *testing.T) (fstest.MapFS, RetainedCatalog, map[string]string) {
	t.Helper()
	recorded := map[string]string{"go.mod": Digest([]byte("original module")), "probe.c": Digest([]byte("original probe"))}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for name, value := range map[string]string{"go.mod": "original module", "probe.c": "original probe"} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	id := SourceSetDigest(recorded)
	archive := OriginalArchive{Path: "original.zip", SHA256: Digest(buf.Bytes()), Sources: clone(recorded), Unavailable: map[string]string{}}
	capture := []byte("original observation")
	catalog := RetainedCatalog{Schema: Schema, Records: []RetainedRecord{{"capture.json", Digest(capture), id}}, Archives: map[string]OriginalArchive{id: archive}}
	encoded, _ := json.Marshal(catalog)
	return fstest.MapFS{"original.zip": &fstest.MapFile{Data: buf.Bytes()}, "capture.json": &fstest.MapFile{Data: capture}, "catalog.json": &fstest.MapFile{Data: encoded}, "go.mod": &fstest.MapFile{Data: []byte("upgraded current module")}}, catalog, recorded
}

func TestRetainedOriginalBytesSurviveToolchainChanges(t *testing.T) {
	source, catalog, recorded := retainedFixture(t)
	parsed, err := ReadCatalog(source, "catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyRetainedCatalog(context.Background(), source, parsed); err != nil {
		t.Fatal(err)
	}
	if err = RequireCompleteOriginals(catalog); err != nil {
		t.Fatal(err)
	}
	original, err := OriginalFS(context.Background(), source, catalog, recorded)
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(original, "go.mod")
	if err != nil || string(b) != "original module" {
		t.Fatal("current bytes replaced original", string(b), err)
	}
	if _, err = fs.ReadFile(original, "missing.go"); err == nil {
		t.Fatal("missing archive source supplied")
	}
}

func TestRetainedCatalogRejections(t *testing.T) {
	source, catalog, _ := retainedFixture(t)
	for _, path := range []string{"missing", "go.mod"} {
		if _, err := ReadCatalog(source, path); err == nil {
			t.Fatal("invalid catalog accepted")
		}
	}
	for _, value := range []RetainedCatalog{{}, {Schema: Schema, Records: catalog.Records}, {Schema: Schema, Archives: catalog.Archives}} {
		b, _ := json.Marshal(value)
		source["bad.json"] = &fstest.MapFile{Data: b}
		if _, err := ReadCatalog(source, "bad.json"); err == nil {
			t.Fatal("incomplete catalog accepted")
		}
	}
	for i, mutate := range []func(*RetainedCatalog){
		func(c *RetainedCatalog) { c.Schema++ }, func(c *RetainedCatalog) { c.Records = nil }, func(c *RetainedCatalog) { c.Records = append(c.Records, c.Records[0]) }, func(c *RetainedCatalog) { c.Records[0].Path = "../unsafe" }, func(c *RetainedCatalog) { c.Records[0].SHA256 = "invalid" }, func(c *RetainedCatalog) { c.Records[0].SHA256 = Digest(nil) }, func(c *RetainedCatalog) { c.Records[0].Path = "missing" }, func(c *RetainedCatalog) { c.Records[0].SourceSet = "missing" }, func(c *RetainedCatalog) { c.Archives["unreferenced"] = c.Archives[c.Records[0].SourceSet] }, func(c *RetainedCatalog) {
			a := c.Archives[c.Records[0].SourceSet]
			a.Sources["probe.c"] = Digest(nil)
			c.Archives[c.Records[0].SourceSet] = a
		}, func(c *RetainedCatalog) {
			a := c.Archives[c.Records[0].SourceSet]
			a.SHA256 = Digest(nil)
			c.Archives[c.Records[0].SourceSet] = a
		},
	} {
		bad := clone(catalog)
		mutate(&bad)
		if err := VerifyRetainedCatalog(context.Background(), source, bad); err == nil {
			t.Fatalf("invalid retained catalog %d accepted", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyRetainedCatalog(ctx, source, catalog); err == nil {
		t.Fatal("cancelled catalog verification accepted")
	}
	bad := clone(catalog)
	a := bad.Archives[bad.Records[0].SourceSet]
	a.Unavailable["lost SDK header"] = Digest(nil)
	bad.Archives[bad.Records[0].SourceSet] = a
	if err := RequireCompleteOriginals(bad); err == nil {
		t.Fatal("incomplete provenance presented as complete")
	}
	if err := RequireCompleteOriginals(RetainedCatalog{}); err == nil {
		t.Fatal("empty original catalog accepted")
	}
	if _, err := OriginalFS(context.Background(), source, catalog, map[string]string{}); err == nil {
		t.Fatal("unregistered sources accepted")
	}
}

func TestOriginalArchiveRejections(t *testing.T) {
	source, catalog, recorded := retainedFixture(t)
	id := SourceSetDigest(recorded)
	for i, mutate := range []func(*OriginalArchive){func(a *OriginalArchive) { a.Path = "../unsafe" }, func(a *OriginalArchive) { a.Path = "missing" }, func(a *OriginalArchive) { a.SHA256 = "invalid" }, func(a *OriginalArchive) { a.SHA256 = Digest(nil) }, func(a *OriginalArchive) { delete(a.Sources, "probe.c") }, func(a *OriginalArchive) { a.Unavailable["probe.c"] = Digest(nil) }, func(a *OriginalArchive) { a.Unavailable["lost"] = "invalid" }, func(a *OriginalArchive) { a.Sources["probe.c"] = Digest(nil) }, func(a *OriginalArchive) { a.Sources["probe.c"] = "invalid" }, func(a *OriginalArchive) { a.Unavailable["lost"] = Digest(nil) }} {
		bad := clone(catalog)
		a := bad.Archives[id]
		mutate(&a)
		bad.Archives[id] = a
		if _, err := OriginalFS(context.Background(), source, bad, recorded); err == nil {
			t.Fatalf("invalid original archive %d accepted", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OriginalFS(ctx, source, catalog, recorded); err == nil {
		t.Fatal("cancelled original archive accepted")
	}
	badSource := clone(source)
	badSource["original.zip"].Data = []byte("not a zip")
	bad := clone(catalog)
	a := bad.Archives[id]
	a.SHA256 = Digest(badSource["original.zip"].Data)
	bad.Archives[id] = a
	if _, err := OriginalFS(context.Background(), badSource, bad, recorded); err == nil {
		t.Fatal("invalid ZIP accepted")
	}
	for _, name := range []string{"../escape", "duplicate", "symlink"} {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if name == "symlink" {
			header.SetMode(fs.ModeSymlink | 0600)
		}
		w, err := z.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("payload"))
		sources := map[string]string{name: Digest([]byte("payload"))}
		if name == "duplicate" {
			w, _ = z.Create(name)
			_, _ = w.Write([]byte("payload"))
			sources["extra"] = Digest(nil)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		badSource := clone(source)
		badSource["original.zip"].Data = buf.Bytes()
		bad := clone(catalog)
		a := bad.Archives[id]
		a.SHA256 = Digest(buf.Bytes())
		a.Sources = sources
		bad.Archives[id] = a
		if _, err = OriginalFS(context.Background(), badSource, bad, recorded); err == nil {
			t.Fatal("unsafe archive accepted", name)
		}
	}
	// Corrupt compressed entry bytes while retaining a valid outer ZIP structure.
	badSource = clone(source)
	payload := append([]byte(nil), badSource["original.zip"].Data...)
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	offset, err := reader.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	payload[offset] ^= 0xff
	badSource["original.zip"].Data = payload
	bad = clone(catalog)
	a = bad.Archives[id]
	a.SHA256 = Digest(payload)
	bad.Archives[id] = a
	if _, err := OriginalFS(context.Background(), badSource, bad, recorded); err == nil {
		t.Fatal("corrupt ZIP entry accepted")
	}
}

func TestExternalOriginalNamesRemainLossless(t *testing.T) {
	source, _, _ := retainedFixture(t)
	recorded := map[string]string{"/SDK/include/native.h": Digest([]byte("original header"))}
	id := SourceSetDigest(recorded)
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	w, _ := z.Create("external/SDK/include/native.h")
	_, _ = w.Write([]byte("original header"))
	_ = z.Close()
	source["external.zip"] = &fstest.MapFile{Data: buf.Bytes()}
	catalog := RetainedCatalog{Schema: Schema, Archives: map[string]OriginalArchive{id: {Path: "external.zip", SHA256: Digest(buf.Bytes()), Sources: map[string]string{"external/SDK/include/native.h": recorded["/SDK/include/native.h"]}}}}
	if _, err := OriginalFS(context.Background(), source, catalog, recorded); err != nil {
		t.Fatal(err)
	}
}

func TestDeduplicatedOriginalArchiveAndParts(t *testing.T) {
	source, catalog, recorded := retainedFixture(t)
	id := SourceSetDigest(recorded)
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, value := range []string{"original module", "original probe"} {
		w, err := z.Create(Digest([]byte(value)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()
	cut := len(body) / 2
	source["part1"] = &fstest.MapFile{Data: body[:cut]}
	source["part2"] = &fstest.MapFile{Data: body[cut:]}
	a := catalog.Archives[id]
	a.Indirect = true
	a.SHA256 = Digest(body)
	a.Parts = []ArchivePart{{"part1", Digest(body[:cut])}, {"part2", Digest(body[cut:])}}
	catalog.Archives[id] = a
	original, err := OriginalFS(context.Background(), source, catalog, recorded)
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(original, "go.mod")
	if err != nil || string(b) != "original module" {
		t.Fatal(string(b), err)
	}
	if err = VerifyRetainedCatalog(context.Background(), source, catalog); err != nil {
		t.Fatal(err)
	}
	for i, mutate := range []func(*OriginalArchive){
		func(a *OriginalArchive) { a.Parts[0].Path = "../unsafe" },
		func(a *OriginalArchive) { a.Parts[0].SHA256 = "invalid" },
		func(a *OriginalArchive) { a.Parts[1] = a.Parts[0] },
		func(a *OriginalArchive) { a.Parts[0].Path = "missing" },
		func(a *OriginalArchive) { a.Parts[0].SHA256 = Digest(nil) },
		func(a *OriginalArchive) { a.Sources["go.mod"] = Digest(nil) },
	} {
		bad := clone(catalog)
		a := bad.Archives[id]
		mutate(&a)
		bad.Archives[id] = a
		if _, err := OriginalFS(context.Background(), source, bad, recorded); err == nil {
			t.Fatalf("invalid split archive %d accepted", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OriginalFS(ctx, source, catalog, recorded); err == nil {
		t.Fatal("cancelled split archive accepted")
	}
	// Duplicate content addresses are rejected even when the transport hash is valid.
	for _, mode := range []string{"duplicate", "invalid-name", "symlink"} {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		name := Digest([]byte("original module"))
		if mode == "invalid-name" {
			name = "invalid"
		}
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if mode == "symlink" {
			header.SetMode(fs.ModeSymlink | 0600)
		}
		w, _ := z.CreateHeader(header)
		_, _ = w.Write([]byte("original module"))
		if mode == "duplicate" {
			w, _ = z.Create(name)
			_, _ = w.Write([]byte("original module"))
		}
		_ = z.Close()
		badSource := clone(source)
		badSource["original.zip"].Data = buf.Bytes()
		bad := clone(catalog)
		a := bad.Archives[id]
		a.Parts = nil
		a.SHA256 = Digest(buf.Bytes())
		bad.Archives[id] = a
		if _, err := OriginalFS(context.Background(), badSource, bad, recorded); err == nil {
			t.Fatal("invalid object store accepted", mode)
		}
	}
}
