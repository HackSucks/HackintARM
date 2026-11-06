package hostdata

import (
	"errors"
	"os"
	"testing"
)

type lifecycleFault struct {
	*LogicalMetadata
	statError, securityError, chmodError error
	writes                               int
}

func (f *lifecycleFault) CaptureStat() (StatCopySource, error) {
	s, _ := f.LogicalMetadata.CaptureStat()
	return s, f.statError
}
func (f *lifecycleFault) CaptureSecurity() (SecurityCopySource, error) {
	s, _ := f.LogicalMetadata.CaptureSecurity()
	return s, f.securityError
}
func (f *lifecycleFault) Chmod(mode uint16) error {
	f.writes++
	if f.writes == 2 && f.chmodError != nil {
		return f.chmodError
	}
	return f.LogicalMetadata.Chmod(mode)
}

func TestHeldLifecycleBoundEndpoints(t *testing.T) {
	source, destination := logicalMetadataFixture(t), logicalMetadataFixture(t)
	if err := destination.Chmod(0400); err != nil {
		t.Fatal(err)
	}
	marker := errors.New("stage failure")
	stages := HeldLifecycleStages{CaptureQuarantine: func() error { return marker }, Run: func(SecurityCopySource) CopyStageResult {
		if mode := destination.Snapshot().Stat.Mode & 0777; mode != 0600 {
			t.Fatal(mode)
		}
		if err := destination.Chmod(0200); err != nil {
			t.Fatal(err)
		}
		return CopyStageResult{Code: -1, Err: marker}
	}}
	result, err := CopyHeldMetadata(source, destination, HeldLifecycleOptions{NoCache: true}, stages)
	if !errors.Is(err, marker) || result.Completed || !result.ModeRestored || result.Code != -1 || destination.Snapshot().Stat.Mode&0777 != 0400 || !source.cacheDisabled || !destination.cacheDisabled {
		t.Fatal(result, err)
	}
	if len(result.Steps) != 7 || result.Steps[2].Err != marker {
		t.Fatal(result.Steps)
	}
	stages.Run = func(SecurityCopySource) CopyStageResult { return CopyStageResult{Code: -7} }
	if result, err = CopyHeldMetadata(source, destination, HeldLifecycleOptions{Stat: true}, stages); err == nil || result.Code != -7 || result.ModeRestored {
		t.Fatal(result, err)
	}
	stages.Run = func(SecurityCopySource) CopyStageResult { return CopyStageResult{Code: 3, Err: marker} }
	if result, err = CopyHeldMetadata(source, destination, HeldLifecycleOptions{}, stages); err != nil || result.Code != 3 || !result.Completed || !result.ModeRestored {
		t.Fatal(result, err)
	}
}

func TestHeldLifecycleValidationAndEffects(t *testing.T) {
	source := logicalMetadataFixture(t)
	stages := HeldLifecycleStages{CaptureQuarantine: func() error { return nil }, Run: func(SecurityCopySource) CopyStageResult { return CopyStageResult{} }}
	for _, call := range []func() (HeldLifecycleResult, error){
		func() (HeldLifecycleResult, error) {
			return CopyHeldMetadata(nil, source, HeldLifecycleOptions{}, stages)
		},
		func() (HeldLifecycleResult, error) {
			return CopyHeldMetadata(source, nil, HeldLifecycleOptions{}, stages)
		},
		func() (HeldLifecycleResult, error) {
			return CopyHeldMetadata(source, source, HeldLifecycleOptions{}, HeldLifecycleStages{})
		},
		func() (HeldLifecycleResult, error) {
			return CopyHeldMetadata(source, source, HeldLifecycleOptions{}, HeldLifecycleStages{CaptureQuarantine: stages.CaptureQuarantine})
		},
	} {
		if _, err := call(); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	}
	marker := errors.New("read failure")
	dest := &lifecycleFault{LogicalMetadata: logicalMetadataFixture(t), statError: marker}
	result, err := CopyHeldMetadata(source, dest, HeldLifecycleOptions{}, stages)
	if !errors.Is(err, marker) || !errors.Is(err, ErrHeldLifecycleUndefined) || dest.writes != 0 || result.Completed {
		t.Fatal(result, err)
	}
	dest.statError = nil
	dest.chmodError = marker
	result, err = CopyHeldMetadata(source, dest, HeldLifecycleOptions{}, stages)
	if err != nil || !result.Completed || result.ModeRestored || !errors.Is(result.Steps[len(result.Steps)-1].Err, marker) {
		t.Fatal(result, err)
	}
}
