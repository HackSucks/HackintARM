package hostdata

import (
	"errors"
	"os"
	"testing"
)

type testedReplacement struct {
	File            *os.File
	RestoreMetadata func() error
	Close           func() error
}

// Exercise the same metadata assertions through both public preparation APIs.
func replacementVariants(t *testing.T, test func(*testing.T, func(*os.File, string) (*testedReplacement, error))) {
	t.Helper()
	for _, rooted := range []bool{false, true} {
		t.Run(map[bool]string{false: "path", true: "root"}[rooted], func(t *testing.T) {
			test(t, func(source *os.File, parent string) (*testedReplacement, error) {
				if !rooted {
					r, err := PrepareReplacement(source, parent)
					if err != nil {
						return nil, err
					}
					return &testedReplacement{r.File, r.RestoreMetadata, r.Close}, nil
				}
				root, err := os.OpenRoot(parent)
				if err != nil {
					return nil, err
				}
				r, err := PrepareReplacementAt(source, root, ".")
				if err != nil {
					return nil, errors.Join(err, root.Close())
				}
				closed := false
				closeOwned := func() error {
					if closed {
						return nil
					}
					closed = true
					return errors.Join(r.Close(), root.Close())
				}
				t.Cleanup(func() {
					if e := closeOwned(); e != nil {
						t.Error(e)
					}
				})
				return &testedReplacement{r.File, r.RestoreMetadata, closeOwned}, nil
			})
		})
	}
}
