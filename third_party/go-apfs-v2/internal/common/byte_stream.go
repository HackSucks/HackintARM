package common

import (
	"encoding/binary"
	"math"
)

// Endian constants
const (
	EndianBig    byte = 'b'
	EndianLittle byte = 'l'
	EndianMiddle byte = 'm'
)

// Uint16BigEndian reads a uint16 from a byte slice in big-endian format
func Uint16BigEndian(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// Uint16LittleEndian reads a uint16 from a byte slice in little-endian format
func Uint16LittleEndian(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

// Uint24BigEndian reads a 24-bit uint from a byte slice in big-endian format
func Uint24BigEndian(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// Uint24LittleEndian reads a 24-bit uint from a byte slice in little-endian format
func Uint24LittleEndian(b []byte) uint32 {
	return uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0])
}

// Uint32BigEndian reads a uint32 from a byte slice in big-endian format
func Uint32BigEndian(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

// Uint32LittleEndian reads a uint32 from a byte slice in little-endian format
func Uint32LittleEndian(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

// Uint48BigEndian reads a 48-bit uint from a byte slice in big-endian format
func Uint48BigEndian(b []byte) uint64 {
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
		uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

// Uint48LittleEndian reads a 48-bit uint from a byte slice in little-endian format
func Uint48LittleEndian(b []byte) uint64 {
	return uint64(b[5])<<40 | uint64(b[4])<<32 | uint64(b[3])<<24 |
		uint64(b[2])<<16 | uint64(b[1])<<8 | uint64(b[0])
}

// Uint64BigEndian reads a uint64 from a byte slice in big-endian format
func Uint64BigEndian(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

// Uint64LittleEndian reads a uint64 from a byte slice in little-endian format
func Uint64LittleEndian(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

// PutUint16BigEndian writes a uint16 to a byte slice in big-endian format
func PutUint16BigEndian(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

// PutUint16LittleEndian writes a uint16 to a byte slice in little-endian format
func PutUint16LittleEndian(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
}

// PutUint24BigEndian writes a 24-bit uint to a byte slice in big-endian format
func PutUint24BigEndian(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// PutUint24LittleEndian writes a 24-bit uint to a byte slice in little-endian format
func PutUint24LittleEndian(b []byte, v uint32) {
	b[2] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[0] = byte(v)
}

// PutUint32BigEndian writes a uint32 to a byte slice in big-endian format
func PutUint32BigEndian(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}

// PutUint32LittleEndian writes a uint32 to a byte slice in little-endian format
func PutUint32LittleEndian(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}

// PutUint48BigEndian writes a 48-bit uint to a byte slice in big-endian format
func PutUint48BigEndian(b []byte, v uint64) {
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}

// PutUint48LittleEndian writes a 48-bit uint to a byte slice in little-endian format
func PutUint48LittleEndian(b []byte, v uint64) {
	b[5] = byte(v >> 40)
	b[4] = byte(v >> 32)
	b[3] = byte(v >> 24)
	b[2] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[0] = byte(v)
}

// PutUint64BigEndian writes a uint64 to a byte slice in big-endian format
func PutUint64BigEndian(b []byte, v uint64) {
	binary.BigEndian.PutUint64(b, v)
}

// PutUint64LittleEndian writes a uint64 to a byte slice in little-endian format
func PutUint64LittleEndian(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}

// Float32FromBits converts a uint32 to float32
func Float32FromBits(b uint32) float32 {
	return math.Float32frombits(b)
}

// Float32Bits converts a float32 to uint32
func Float32Bits(f float32) uint32 {
	return math.Float32bits(f)
}

// Float64FromBits converts a uint64 to float64
func Float64FromBits(b uint64) float64 {
	return math.Float64frombits(b)
}

// Float64Bits converts a float64 to uint64
func Float64Bits(f float64) uint64 {
	return math.Float64bits(f)
}

// RotateLeft8 rotates an 8-bit value left by the specified number of bits
func RotateLeft8(value uint8, bits uint) uint8 {
	return (value << bits) | (value >> (8 - bits))
}

// RotateRight8 rotates an 8-bit value right by the specified number of bits
func RotateRight8(value uint8, bits uint) uint8 {
	return (value >> bits) | (value << (8 - bits))
}

// RotateLeft16 rotates a 16-bit value left by the specified number of bits
func RotateLeft16(value uint16, bits uint) uint16 {
	return (value << bits) | (value >> (16 - bits))
}

// RotateRight16 rotates a 16-bit value right by the specified number of bits
func RotateRight16(value uint16, bits uint) uint16 {
	return (value >> bits) | (value << (16 - bits))
}

// RotateLeft32 rotates a 32-bit value left by the specified number of bits
func RotateLeft32(value uint32, bits uint) uint32 {
	return (value << bits) | (value >> (32 - bits))
}

// RotateRight32 rotates a 32-bit value right by the specified number of bits
func RotateRight32(value uint32, bits uint) uint32 {
	return (value >> bits) | (value << (32 - bits))
}

// RotateLeft64 rotates a 64-bit value left by the specified number of bits
func RotateLeft64(value uint64, bits uint) uint64 {
	return (value << bits) | (value >> (64 - bits))
}

// RotateRight64 rotates a 64-bit value right by the specified number of bits
func RotateRight64(value uint64, bits uint) uint64 {
	return (value >> bits) | (value << (64 - bits))
}
