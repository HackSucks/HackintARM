package hostdata

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
)

// ErrXattrMutationUncaptured means the destination no longer matches the
// explicit before-state of a captured filesystem mutation observation.
var ErrXattrMutationUncaptured = errors.New("xattr mutation context was not captured")

// CapturedDarwinErrno retains the number of an observed Darwin error without
// interpreting it as an errno from the receiving Linux or Windows system.
// It intentionally has no implicit mapping to local syscall or permission errors.
type CapturedDarwinErrno uint32

func (e CapturedDarwinErrno) Error() string {
	return fmt.Sprintf("captured Darwin errno %d", uint32(e))
}

// CapturedXattrMutation describes one observed filesystem mutation effect.
// A successful removal does not necessarily make an attribute disappear. Some
// native providers retain or recreate an attribute even after returning zero.
// Presence is explicit so an empty value remains distinct from an absent value.
// Errno is the captured Darwin errno (zero for success), not the current host's
// errno numbering. Observations must come from the caller's captured filesystem,
// security and process context; no policy is inferred from attribute names.
//
// The observation is reusable only while its exact before-value still matches.
// A second removal after a state-changing first call therefore fails explicitly;
// a successful unchanged-value observation can be replayed repeatedly.
// Names must be unique. Construction owns copies of both value byte slices.
type CapturedXattrMutation struct {
	Name                        string
	BeforePresent, AfterPresent bool
	Before, After               []byte
	Errno                       uint32
}

// CapturedXattrRemoval is the observed effect of a fremovexattr operation.
type CapturedXattrRemoval = CapturedXattrMutation

// CapturedXattrWrite binds a fsetxattr operation (position zero, flags zero) to
// both its exact incoming bytes and its observed before/after state. Native
// attribute operations with other flags or positions require other evidence.
type CapturedXattrWrite struct {
	Effect CapturedXattrMutation
	Input  []byte
}

func cloneCapturedMutation(o CapturedXattrMutation) (CapturedXattrMutation, error) {
	if validXattrName(o.Name) != nil || (!o.BeforePresent && len(o.Before) != 0) || (!o.AfterPresent && len(o.After) != 0) || o.Errno > math.MaxInt32 {
		return CapturedXattrMutation{}, os.ErrInvalid
	}
	o.Before, o.After = bytes.Clone(o.Before), bytes.Clone(o.After)
	return o, nil
}

func captureXattrRemovals(a *logicalObjectAttributes, observations []CapturedXattrRemoval) error {
	a.removals = make(map[string]CapturedXattrRemoval, len(observations))
	for _, o := range observations {
		owned, err := cloneCapturedMutation(o)
		if err != nil {
			return err
		}
		if _, exists := a.removals[o.Name]; exists {
			return ErrXattrListMalformed
		}
		a.removals[o.Name] = owned
	}
	return nil
}

func captureXattrWrites(a *logicalObjectAttributes, observations []CapturedXattrWrite) error {
	a.writes = make(map[string]CapturedXattrWrite, len(observations))
	for _, o := range observations {
		owned, err := cloneCapturedMutation(o.Effect)
		if err != nil {
			return err
		}
		if _, exists := a.writes[owned.Name]; exists {
			return ErrXattrListMalformed
		}
		a.writes[owned.Name] = CapturedXattrWrite{Effect: owned, Input: bytes.Clone(o.Input)}
	}
	return nil
}

func (a *logicalObjectAttributes) applyObserved(o CapturedXattrMutation) error {
	value, present := a.values[o.Name]
	if present != o.BeforePresent {
		return ErrXattrMutationUncaptured
	}
	if present {
		if value.Size() != int64(len(o.Before)) {
			return ErrXattrMutationUncaptured
		}
		b := make([]byte, len(o.Before))
		n, err := value.ReadAt(b, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return errors.Join(ErrXattrMutationUncaptured, err)
		}
		if n != len(b) || !bytes.Equal(b, o.Before) {
			return ErrXattrMutationUncaptured
		}
	}
	if o.AfterPresent {
		a.values[o.Name] = bytes.NewReader(bytes.Clone(o.After))
		if !present {
			a.order = append(a.order, o.Name)
		}
	} else {
		delete(a.values, o.Name)
		a.order = slices.DeleteFunc(a.order, func(n string) bool { return n == o.Name })
	}
	if o.Errno != 0 {
		return CapturedDarwinErrno(o.Errno)
	}
	return nil
}
