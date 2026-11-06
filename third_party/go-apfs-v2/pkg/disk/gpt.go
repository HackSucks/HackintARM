// GPT (GUID Partition Table) parser
package disk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

const (
	gptSignature  = "EFI PART"
	gptSectorSize = 0x200
	// gptMaxEntries bounds the partition table a header may claim, since the
	// table is allocated before it is read. Disks use 128 entries; this allows
	// a 2 MiB table.
	gptMaxEntries = 16384
)

const (
	appleAPFSGUID = "7C3457EF-0000-11AA-AA11-00306543ECAC"
	appleHFSGUID  = "48465300-0000-11AA-AA11-00306543ECAC"
	noneGUID      = "00000000-0000-0000-0000-000000000000"
)

type gptGUID [16]byte

func (u gptGUID) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[3], u[2], u[1], u[0],
		u[5], u[4],
		u[7], u[6],
		u[8], u[9],
		u[10], u[11], u[12], u[13], u[14], u[15],
	)
}

type gptMagic [8]byte

// GPTHeader is a GPT header structure
type GPTHeader struct {
	Signature       gptMagic
	Revision        uint32
	HeaderSize      uint32
	CRC32           uint32
	Reserved        uint32
	HeaderStartLBA  uint64
	BackupLBA       uint64
	FirstUsableLBA  uint64
	LastUsableLBA   uint64
	DiskGUID        gptGUID
	EntriesStart    uint64
	EntriesCount    uint32
	EntriesSize     uint32
	PartitionsCRC32 uint32
	Padding         [420]byte
}

// Verify verifies the GPT header
func (h GPTHeader) Verify() error {
	if h.EntriesSize != 128 {
		return fmt.Errorf("unsupported GPT format, must be 128 byte entries")
	}

	if h.EntriesCount > gptMaxEntries {
		return fmt.Errorf("GPT claims %d partition entries; at most %d are supported", h.EntriesCount, gptMaxEntries)
	}

	if gptSectorSize-len(h.Padding) != int(h.HeaderSize) {
		return fmt.Errorf("invalid header size")
	}

	if string(h.Signature[:]) != gptSignature {
		return fmt.Errorf("invalid GPT signature: %s", h.Signature)
	}

	return nil
}

// GPTPartition is a GPT partition entry
type GPTPartition struct {
	Type               gptGUID
	ID                 gptGUID
	StartingLBA        uint64
	EndingLBA          uint64
	Attributes         uint64
	PartitionNameUTF16 [72]uint8
}

// IsEmpty returns if the partition is empty
func (p GPTPartition) IsEmpty() bool {
	return p.Type == gptGUID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// Name returns the partition's name
func (p GPTPartition) Name() string {
	n, err := decodeUTF16(p.PartitionNameUTF16[:], binary.LittleEndian)
	if err != nil {
		return "<unable to decode UTF-16 partition name>"
	}
	return n
}

func decodeUTF16(b []byte, order binary.ByteOrder) (string, error) {
	ints := make([]uint16, len(b)/2)
	if err := binary.Read(bytes.NewReader(b), order, &ints); err != nil {
		return "", err
	}
	return string(utf16.Decode(ints)), nil
}
