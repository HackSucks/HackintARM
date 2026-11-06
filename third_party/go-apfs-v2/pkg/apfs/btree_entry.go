package apfs

import (
	"fmt"
)

// BTreeEntry represents a B-tree entry (key-value pair)
type BTreeEntry struct {
	// The key data
	KeyData []byte

	// The value data
	ValueData []byte
}

// NewBTreeEntry creates a new B-tree entry
func NewBTreeEntry() *BTreeEntry {
	return &BTreeEntry{}
}

// SetKeyData sets the key data for this entry
func (e *BTreeEntry) SetKeyData(keyData []byte) error {
	if e.KeyData != nil {
		return fmt.Errorf("key data value already set")
	}

	if keyData == nil {
		return fmt.Errorf("invalid key data")
	}

	e.KeyData = make([]byte, len(keyData))
	copy(e.KeyData, keyData)

	return nil
}

// SetValueData sets the value data for this entry
func (e *BTreeEntry) SetValueData(valueData []byte) error {
	if e.ValueData != nil {
		return fmt.Errorf("value data value already set")
	}

	if valueData == nil {
		return fmt.Errorf("invalid value data")
	}

	e.ValueData = make([]byte, len(valueData))
	copy(e.ValueData, valueData)

	return nil
}
