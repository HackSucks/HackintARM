package hostdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type borrowedReplacementValue struct {
	size  int64
	data  []byte
	err   error
	read  func()
	sized func()
	reads int
}

func (v *borrowedReplacementValue) Size() int64 {
	if v.sized != nil {
		v.sized()
	}
	return v.size
}
func (v *borrowedReplacementValue) ReadAt(p []byte, at int64) (int, error) {
	v.reads++
	if v.read != nil {
		v.read()
	}
	if v.err != nil {
		return 0, v.err
	}
	if at < 0 || at >= int64(len(v.data)) {
		return 0, io.EOF
	}
	n := copy(p, v.data[at:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestReplacementBorrowedAttributes(t *testing.T) {
	for _, sample := range replacementCompressionSamples(t) {
		for _, active := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/active-%t", sample.Name, active), func(t *testing.T) {
				fork := &borrowedReplacementValue{size: 1 << 40}
				ordinary := &borrowedReplacementValue{size: 8 << 30}
				attribute := &borrowedReplacementValue{size: int64(len(sample.Attribute)), data: sample.Attribute}
				input := map[string]appledouble.Value{DecmpfsName: attribute, ResourceForkName: fork, "user.value": ordinary}
				flags := uint32(0)
				if active {
					flags = UFCompressed
				}
				result, err := ReplacementAttributeValues(t.Context(), flags, input)
				if err != nil {
					t.Fatal(err)
				}
				if result["user.value"] != ordinary || ordinary.reads != 0 || fork.reads != 0 {
					t.Fatal("materialized borrowed value")
				}
				want := 3
				if active {
					want -= 2
				}
				if len(result) != want || (result[DecmpfsName] == nil) != active || (result[ResourceForkName] == nil) != active {
					t.Fatal("wrong selection", result)
				}
				if active && attribute.reads != 1 || !active && attribute.reads != 0 {
					t.Fatal("header reads", attribute.reads)
				}
				delete(result, "user.value")
				if len(input) != 3 || !bytes.Equal(attribute.data, sample.Attribute) {
					t.Fatal("modified source")
				}
			})
		}
	}
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("reserved-prefixes/active-%t", active), func(t *testing.T) {
			header := make([]byte, 16)
			copy(header, "fpmc")
			binary.LittleEndian.PutUint32(header[4:], 3)
			values := map[string]appledouble.Value{DecmpfsName: bytes.NewReader(header), DecmpfsName + ".extra": bytes.NewReader(nil), ResourceForkName + ".extra": bytes.NewReader(nil), "user.com.apple.ResourceFork": bytes.NewReader(nil)}
			flags := uint32(0)
			if active {
				flags = UFCompressed
			}
			result, err := ReplacementAttributeValues(t.Context(), flags, values)
			want := 4
			if active {
				want = 1
			}
			if err != nil || len(result) != want || result["user.com.apple.ResourceFork"] == nil {
				t.Fatal(result, err)
			}
		})
	}
	t.Run("inactive-opaque", func(t *testing.T) {
		value := &borrowedReplacementValue{size: 1, err: io.ErrUnexpectedEOF}
		result, err := ReplacementAttributeValues(t.Context(), 0, map[string]appledouble.Value{DecmpfsName: value})
		if err != nil || result[DecmpfsName] != value || value.reads != 0 {
			t.Fatal(result, err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		result, err := ReplacementAttributeValues(t.Context(), 0, nil)
		if err != nil || len(result) != 0 {
			t.Fatal(result, err)
		}
	})
}

func TestReplacementBorrowedAttributeFailures(t *testing.T) {
	for _, name := range []string{"missing-header", "short-header", "read-error", "bad-magic", "unknown-type", "nil-value", "negative-size", "cancel-before", "cancel-header", "cancel-value", "cancel-loop"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			header := make([]byte, 16)
			copy(header, "fpmc")
			binary.LittleEndian.PutUint32(header[4:], 4)
			binary.LittleEndian.PutUint64(header[8:], 65536)
			value := &borrowedReplacementValue{size: 16, data: header}
			input := map[string]appledouble.Value{DecmpfsName: value}
			flags := uint32(UFCompressed)
			var want error
			switch name {
			case "missing-header":
				delete(input, DecmpfsName)
			case "short-header":
				value.size = 15
			case "read-error":
				value.err, want = io.ErrClosedPipe, io.ErrClosedPipe
			case "bad-magic":
				header[0] = 'x'
			case "unknown-type":
				binary.LittleEndian.PutUint32(header[4:], 999)
			case "nil-value":
				flags = 0
				input = map[string]appledouble.Value{"x": nil}
				want = fs.ErrInvalid
			case "negative-size":
				flags = 0
				value.size = -1
				want = fs.ErrInvalid
			case "cancel-before":
				cancel()
				want = context.Canceled
			case "cancel-header":
				value.read = cancel
				want = context.Canceled
			case "cancel-value":
				flags = 0
				value.sized = cancel
				want = context.Canceled
			case "cancel-loop":
				flags = 0
				value.sized = cancel
				input["second"] = value
				want = context.Canceled
			}
			result, err := ReplacementAttributeValues(ctx, flags, input)
			if err == nil || result != nil || want != nil && !errors.Is(err, want) {
				t.Fatal(result, err)
			}
		})
	}
}
