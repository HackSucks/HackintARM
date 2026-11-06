package unpackrestore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// SequentialImages extends the reviewed valid-source corpus with late malformed
// headers/records/reads. These are inputs, never generated expected outcomes.
func SequentialImages() []string {
	encode := func(f appledouble.File) []byte {
		b, err := f.Encode()
		if err != nil {
			panic(err)
		}
		return b
	}
	attrs := encode(appledouble.File{Attrs: []appledouble.Attr{{Name: "a", Value: []byte{1}}, {Name: "b", Value: []byte{2}}}})
	fork := encode(appledouble.File{ResourceFork: []byte{7, 8, 9}})
	aclFork := encode(appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: []byte("acl")}}, ResourceFork: []byte{7, 8, 9}})
	filtered := encode(appledouble.File{Attrs: []appledouble.Attr{{Name: "filtered#N", Value: []byte{1}}}})
	edit := func(b []byte, mutate func([]byte)) []byte {
		b = bytes.Clone(b)
		mutate(b)
		return b
	}
	inputs := [][]byte{
		attrs, attrs[:len(attrs)-1],
		edit(attrs, func(b []byte) { b[146] = 1 }),
		edit(attrs, func(b []byte) { b[148] = 1 }),
		edit(attrs, func(b []byte) { binary.BigEndian.PutUint32(b[30:], ^uint32(0)) }),
		edit(attrs, func(b []byte) { b[119] = 3 }),
		edit(attrs, func(b []byte) { b[84] = 0 }),
		attrs[:82], attrs[:81],
		edit(attrs, func(b []byte) { b[0] = 1 }),
		fork, fork[:len(fork)-1],
		aclFork, aclFork[:len(aclFork)-1],
		filtered[:len(filtered)-1],
		edit(attrs, func(b []byte) { binary.BigEndian.PutUint32(b[136:], ^uint32(0)) }),
		edit(fork, func(b []byte) { binary.BigEndian.PutUint32(b[42:], ^uint32(0)) }),
	}
	result := make([]string, len(inputs))
	for i, b := range inputs {
		result[i] = hex.EncodeToString(b)
	}
	return result
}

// SequentialCases exercises actual pread short reads, value offsets, header
// validation and cleanup before late errors through the unchanged Apple body.
func SequentialCases(live bool) []Case {
	var cases []Case
	for image := range SequentialImages() {
		// The live helper independently verifies seed removal; malformed base
		// headers intentionally never reach cleanup, and remain controlled cases.
		if live && (image == 8 || image == 9) {
			continue
		}
		for _, stat := range []bool{false, true} {
			cases = append(cases, Case{Image: image, List: 1, StatFlag: stat})
		}
	}
	return cases
}
