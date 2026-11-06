package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCodeJoinedCleanup(t *testing.T) {
	primary := withCode(ExitPartial, errors.New("entry skipped"))
	for _, err := range []error{primary, fmt.Errorf("packing: %w", primary), errors.Join(primary, nil), errors.Join(primary, errors.New("close failed"))} {
		if got := exitCodeFor(err); got != ExitPartial {
			t.Fatalf("%v: code %d", err, got)
		}
	}
	if exitCodeFor(nil) != ExitOK || exitCodeFor(errors.New("failure")) != ExitError || withCode(ExitPartial, nil) != nil {
		t.Fatal("default exit codes")
	}
}
