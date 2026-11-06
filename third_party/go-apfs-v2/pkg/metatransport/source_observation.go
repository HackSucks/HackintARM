package metatransport

import (
	"context"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ObservedSourceAttribute returns a bounded borrowed value and whether the
// source's complete attribute enumeration was observed. A nil value with
// captured=true is observed absence; captured=false is unknown, including every
// older carrier that omitted SourceAttributesCaptured. NativeAttributes and
// NativeCaptured describe the receiving host and never establish this fact.
// Errors return captured=false and must not be interpreted as absence.
func (s *Store) ObservedSourceAttribute(ctx context.Context, record Record, name string) (value appledouble.Value, captured bool, err error) {
	if err = s.check(ctx); err != nil {
		return nil, false, err
	}
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return nil, false, ErrInvalid
	}
	if !record.SourceAttributesCaptured {
		return nil, false, nil
	}
	values, err := s.BorrowRecordAttributes(ctx, record)
	if err != nil {
		return nil, false, err
	}
	return values[name], true, nil
}
