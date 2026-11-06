package hfsplus

import (
	"bytes"
	"fmt"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// XattrValues returns borrowed, immutable sized attribute readers. The volume's
// underlying image must remain open until all values have been consumed. Fork
// attributes and resource forks are read on demand rather than allocated whole.
func (v *Volume) XattrValues(name string) (map[string]appledouble.Value, error) {
	e, err := v.entryByFSName("xattrvalues", name)
	if err != nil {
		return nil, err
	}
	values, err := v.xattrValues(e)
	if err != nil {
		return nil, &fs.PathError{Op: "xattrvalues", Path: name, Err: err}
	}
	return values, nil
}
func (v *Volume) xattrValues(e *entry) (map[string]appledouble.Value, error) {
	id, ok := entryFileID(e)
	if !ok {
		return nil, fmt.Errorf("entry has no catalog record")
	}
	if err := v.loadAttributes(); err != nil {
		return nil, err
	}
	out := make(map[string]appledouble.Value, len(v.attrNames[id])+1)
	finder := map[string][]byte{}
	for _, name := range v.attrNames[id] {
		value, err := v.attributeReader(id, name)
		if err != nil {
			return nil, err
		}
		if name == finderInfoName {
			if value.Size() > 32 {
				return nil, fmt.Errorf("HFS catalog and noncanonical attribute-tree FinderInfo conflict")
			}
			b := make([]byte, value.Size())
			if err = readValue(value, b); err != nil {
				return nil, err
			}
			finder[name] = b
		} else {
			out[name] = value
		}
	}
	if err := addCatalogFinderInfo(finder, e); err != nil {
		return nil, err
	}
	for name, b := range finder {
		out[name] = bytes.NewReader(b)
	}
	if !e.isDir && e.file != nil && e.file.ResourceFork.LogicalSize > 0 {
		fork, err := v.resourceForkReader(e)
		if err != nil {
			return nil, err
		}
		out[resourceForkAttrName] = fork
	}
	return out, nil
}
func (v *Volume) attributeReader(fileID CatalogNodeID, name string) (appledouble.Value, error) {
	rec := v.attributes[attrKey{fileID: fileID, name: name}]
	if rec == nil {
		return nil, fmt.Errorf("file %d has no attribute %q", fileID, name)
	}
	if rec.inline != nil {
		return bytes.NewReader(rec.inline), nil
	}
	if !rec.hasFork {
		return nil, fmt.Errorf("attribute %q has neither inline data nor a fork", name)
	}
	extents := inlineExtents(rec.fork)
	var blocks uint64
	for _, ext := range extents {
		blocks += uint64(ext.BlockCount)
	}
	for _, run := range rec.overflow {
		if uint64(run.startBlock) != blocks {
			continue
		}
		for _, ext := range run.extents {
			if ext.BlockCount == 0 {
				break
			}
			extents = append(extents, ext)
			blocks += uint64(ext.BlockCount)
		}
	}
	if blocks < uint64(rec.fork.TotalBlocks) {
		return nil, fmt.Errorf("attribute %q: extents cover %d of %d blocks", name, blocks, rec.fork.TotalBlocks)
	}
	reader, err := newForkReader(v.dev, v.blockSize, rec.fork.LogicalSize, extents)
	if err != nil {
		return nil, fmt.Errorf("attribute %q: %w", name, err)
	}
	return reader, nil
}
