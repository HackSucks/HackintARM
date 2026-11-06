//go:build !windows

package hostdata

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type replacementPlatformState struct {
	source *os.File
	info   os.FileInfo
	dir    string
}

func prepareReplacementPrivateContext(ctx context.Context, source *os.File, parent string, info os.FileInfo, _ ReplacementOptions) (*Replacement, error) {
	dir, err := os.MkdirTemp(parent, ".apfs-replacement-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "replacement")
	f, err := prepareReplacementContext(ctx, source, path, info)
	err = errors.Join(err, ctx.Err())
	if err != nil {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		return nil, errors.Join(fmt.Errorf("prepare replacement: %w", err), cleanupReplacement(
			func() error { return os.Chmod(path, 0600) }, func() error { return os.RemoveAll(dir) }))
	}
	return &Replacement{File: f, replacementPlatformState: replacementPlatformState{source: source, info: info, dir: dir}}, nil
}

func makeReplacementDirectoryAt(ctx context.Context, root *os.Root, name string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := root.Mkdir(name, 0700); err != nil {
		return nil, err
	}
	return func() error { return nil }, ctx.Err()
}

func replacementCleanupCapability(_ *os.File) (*os.File, error) { return nil, nil }
func replacementCleanupMetadata(stage *os.Root, _ *os.File) error {
	return stage.Chmod("replacement", 0600)
}

func restorePrivateReplacementContext(ctx context.Context, r *Replacement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := replacementValue(ctx, r.source.Stat)
	if err != nil {
		return err
	}
	if !os.SameFile(r.info, current) {
		return fmt.Errorf("replacement source changed")
	}
	return restoreReplacementMetadataContext(ctx, r.source, r.File, r.info)
}

func closePrivateReplacement(r *Replacement) error {
	err := r.File.Close()
	if errors.Is(err, os.ErrClosed) {
		err = nil
	}
	return errors.Join(err, cleanupReplacement(
		func() error { return os.Chmod(filepath.Join(r.dir, "replacement"), 0600) }, func() error { return os.RemoveAll(r.dir) }))
}

func preparePrivateFilesystemReplacement(ctx context.Context, r *Replacement, source *os.File, options ReplacementOptions) error {
	profile, err := options.filesystemProfile()
	if err != nil {
		return err
	}
	r.filesystem, err = prepareReplacementFilesystemForProfile(ctx, source, r.File, profile)
	return err
}
