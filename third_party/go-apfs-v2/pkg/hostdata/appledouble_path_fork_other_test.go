//go:build !darwin

package hostdata

import (
	"errors"
	"testing"
)

func TestPathResourceForkForeignBinding(t *testing.T) {
	p := &appleDoublePath{}
	if _, e := p.openFork(nil, false); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
}
