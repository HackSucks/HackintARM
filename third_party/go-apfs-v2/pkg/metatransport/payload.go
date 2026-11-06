package metatransport

import (
	"context"
	"errors"
	"os"
)

// OpenPayload opens a regular materialized payload for read/write use through
// the held root. It rejects redirected parents and verifies pathname/descriptor
// identity. The caller owns the file and excludes unrelated namespace edits.
func (s *Store) OpenPayload(ctx context.Context, name string) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(ctx); e != nil {
		return nil, e
	}
	if !validPath(name) {
		return nil, ErrInvalid
	}
	if e := checkParents(s.payload, name); e != nil {
		return nil, e
	}
	before, e := s.payload.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, ErrConflict
	}
	file, e := s.payload.OpenFile(name, os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	after, e := file.Stat()
	if e != nil {
		return nil, errors.Join(e, file.Close())
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.Join(ErrConflict, file.Close())
	}
	return file, nil
}

// CheckPayload checks that a held descriptor still names the same regular
// materialized payload. It does not promise a namespace snapshot or verify data.
func (s *Store) CheckPayload(ctx context.Context, name string, file interface{ Stat() (os.FileInfo, error) }) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.ready(ctx); e != nil {
		return e
	}
	if !validPath(name) || file == nil {
		return ErrInvalid
	}
	if e := checkParents(s.payload, name); e != nil {
		return e
	}
	current, e := s.payload.Lstat(name)
	if e != nil {
		return e
	}
	held, e := file.Stat()
	if e != nil {
		return e
	}
	if !current.Mode().IsRegular() || !held.Mode().IsRegular() || !os.SameFile(current, held) {
		return ErrConflict
	}
	return nil
}

// Publish verifies the next manifest and expected generation and prepares its
// durable bytes before calling transition under the exclusive writer lock.
// Only a successful transition permits publication. The callback may use read
// methods and caller-owned held payloads; it must not call Store write methods
// or Close recursively. Store.Close cannot invalidate roots during the callback.
//
// Payload effects are not rolled back if the callback or final rename fails.
// The caller must validate held associations and content immediately before
// mutation. Cancellation before transition prevents it; transition owns its
// cancellation boundary once mutation starts. published reports a successful
// rename even if subsequent lock cleanup returns an error. A nil callback
// publishes metadata only, with the same behavior as Commit.
func (s *Store) Publish(ctx context.Context, m Manifest, expected uint64, transition func() error) (published bool, err error) {
	return s.commitWithPayload(ctx, m, expected, transition)
}
