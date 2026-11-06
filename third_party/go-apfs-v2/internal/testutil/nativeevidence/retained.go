package nativeevidence

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// RetainedRecord pins the original observation, including its original source
// map. Migration adds this ledger without editing historical observations.
type RetainedRecord struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SourceSet string `json:"source_set"`
}
type OriginalArchive struct {
	Indirect    bool              `json:"indirect,omitempty"`
	Parts       []ArchivePart     `json:"parts,omitempty"`
	Path        string            `json:"path"`
	SHA256      string            `json:"sha256"`
	Sources     map[string]string `json:"sources"`
	Unavailable map[string]string `json:"unavailable"`
}
type ArchivePart struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type RetainedCatalog struct {
	Schema   int                        `json:"schema"`
	Records  []RetainedRecord           `json:"records"`
	Archives map[string]OriginalArchive `json:"archives"`
}

// SourceSetDigest identifies original provenance, not current implementation.
func SourceSetDigest(sources map[string]string) string {
	b, _ := json.Marshal(sources)
	return Digest(b)
}

func ReadCatalog(source fs.FS, path string) (RetainedCatalog, error) {
	var catalog RetainedCatalog
	b, err := fs.ReadFile(source, path)
	if err != nil {
		return catalog, err
	}
	if err = json.Unmarshal(b, &catalog); err != nil {
		return catalog, err
	}
	if catalog.Schema != Schema || len(catalog.Records) == 0 || len(catalog.Archives) == 0 {
		return catalog, fmt.Errorf("incomplete retained catalog")
	}
	return catalog, nil
}

// OriginalFS exposes only hash-verified original source bytes. No missing
// archived input is substituted with current checkout bytes.
func OriginalFS(ctx context.Context, source fs.FS, catalog RetainedCatalog, recorded map[string]string) (fs.FS, error) {
	id := SourceSetDigest(recorded)
	archive, ok := catalog.Archives[id]
	if !ok || catalog.Schema != Schema {
		return nil, fmt.Errorf("unregistered original source set %s", id)
	}
	if !fs.ValidPath(archive.Path) || !validDigest(archive.SHA256) {
		return nil, fmt.Errorf("invalid original archive identity")
	}
	b, err := readOriginalArchive(ctx, source, archive)
	if err != nil {
		return nil, err
	}
	if Digest(b) != archive.SHA256 {
		return nil, fmt.Errorf("corrupted original source archive %s", archive.Path)
	}
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, err
	}
	if !archive.Indirect && len(z.File) != len(archive.Sources) {
		return nil, fmt.Errorf("incomplete or unexpected archived source inventory")
	}
	if archive.Indirect {
		objects := map[string]*zip.File{}
		for _, f := range z.File {
			if objects[f.Name] != nil || !validDigest(f.Name) || !f.Mode().IsRegular() {
				return nil, fmt.Errorf("invalid or duplicate original object %s", f.Name)
			}
			objects[f.Name] = f
		}
		view := &zip.Reader{}
		for name, hash := range archive.Sources {
			f := objects[hash]
			if f == nil {
				return nil, fmt.Errorf("missing original object %s", name)
			}
			copy := *f
			copy.Name = name
			view.File = append(view.File, &copy)
		}
		z = view
	}
	seen := map[string]bool{}
	original := map[string]string{}
	for _, f := range z.File {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		want, ok := archive.Sources[f.Name]
		if !ok || seen[f.Name] || !fs.ValidPath(f.Name) || !f.Mode().IsRegular() || !validDigest(want) {
			return nil, fmt.Errorf("unsafe, duplicate or unexpected archived source %s", f.Name)
		}
		seen[f.Name] = true
		data, err := fs.ReadFile(z, f.Name)
		if err != nil {
			return nil, err
		}
		if Digest(data) != want {
			return nil, fmt.Errorf("corrupted original source %s", f.Name)
		}
		name := f.Name
		if strings.HasPrefix(name, "external/") {
			name = "/" + strings.TrimPrefix(name, "external/")
		}
		original[name] = want
	}
	for name, hash := range archive.Unavailable {
		if _, ok := original[name]; ok || !validDigest(hash) {
			return nil, fmt.Errorf("conflicting or invalid unavailable original source %s", name)
		}
		original[name] = hash
	}
	if SourceSetDigest(original) != id {
		return nil, fmt.Errorf("original archive does not match recorded provenance")
	}
	return z, nil
}

func readOriginalArchive(ctx context.Context, source fs.FS, archive OriginalArchive) ([]byte, error) {
	if len(archive.Parts) == 0 {
		return fs.ReadFile(source, archive.Path)
	}
	var result []byte
	seen := map[string]bool{}
	for _, part := range archive.Parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !fs.ValidPath(part.Path) || !validDigest(part.SHA256) || seen[part.Path] {
			return nil, fmt.Errorf("invalid or duplicate original archive part %s", part.Path)
		}
		seen[part.Path] = true
		b, err := fs.ReadFile(source, part.Path)
		if err != nil {
			return nil, err
		}
		if Digest(b) != part.SHA256 {
			return nil, fmt.Errorf("corrupted original archive part %s", part.Path)
		}
		result = append(result, b...)
	}
	return result, nil
}

// VerifyRetainedCatalog checks every original capture and archive, independently
// of the current Go toolchain. Unavailable legacy bytes remain disclosed in the
// catalog and cannot satisfy RequireCompleteOriginals or a fresh Bundle.
func VerifyRetainedCatalog(ctx context.Context, source fs.FS, catalog RetainedCatalog) error {
	if catalog.Schema != Schema || len(catalog.Records) == 0 {
		return fmt.Errorf("invalid retained catalog")
	}
	seen := map[string]bool{}
	used := map[string]bool{}
	for _, record := range catalog.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !fs.ValidPath(record.Path) || seen[record.Path] || !validDigest(record.SHA256) {
			return fmt.Errorf("invalid or duplicate retained record %s", record.Path)
		}
		seen[record.Path] = true
		b, err := fs.ReadFile(source, record.Path)
		if err != nil {
			return err
		}
		if Digest(b) != record.SHA256 {
			return fmt.Errorf("changed retained native observation %s", record.Path)
		}
		archive, ok := catalog.Archives[record.SourceSet]
		if !ok {
			return fmt.Errorf("missing original provenance %s", record.Path)
		}
		if !used[record.SourceSet] {
			sources := map[string]string{}
			for name, hash := range archive.Sources {
				if strings.HasPrefix(name, "external/") {
					name = "/" + strings.TrimPrefix(name, "external/")
				}
				sources[name] = hash
			}
			for name, hash := range archive.Unavailable {
				sources[name] = hash
			}
			if SourceSetDigest(sources) != record.SourceSet {
				return fmt.Errorf("changed original source identity %s", record.Path)
			}
			if _, err := OriginalFS(ctx, source, catalog, sources); err != nil {
				return err
			}
			used[record.SourceSet] = true
		}
	}
	if len(used) != len(catalog.Archives) {
		return fmt.Errorf("unreferenced original source archive")
	}
	return nil
}

// RequireCompleteOriginals distinguishes recovered historical references from
// complete capture provenance. It is mandatory before promoting native evidence
// as a complete qualification bundle.
func RequireCompleteOriginals(catalog RetainedCatalog) error {
	if catalog.Schema != Schema || len(catalog.Archives) == 0 {
		return fmt.Errorf("invalid original catalog")
	}
	for id, archive := range catalog.Archives {
		if len(archive.Unavailable) > 0 {
			return fmt.Errorf("incomplete original provenance %s: %d source entries unavailable", id, len(archive.Unavailable))
		}
	}
	return nil
}
