package common

// Integer limit constants
// These correspond to the C standard library limits defined in types.h

const (
	// Int8Max is the maximum signed 8-bit integer (127, 0x7f)
	Int8Max = 0x7f

	// Uint8Max is the maximum unsigned 8-bit integer (255, 0xff)
	Uint8Max = 0xff

	// Int16Max is the maximum signed 16-bit integer (32767, 0x7fff)
	Int16Max = 0x7fff

	// Uint16Max is the maximum unsigned 16-bit integer (65535, 0xffff)
	Uint16Max = 0xffff

	// Int32Max is the maximum signed 32-bit integer (2147483647, 0x7fffffff)
	// This is also used as SSIZE_MAX equivalent on 32-bit systems
	Int32Max = 0x7fffffff

	// Uint32Max is the maximum unsigned 32-bit integer (4294967295, 0xffffffff)
	Uint32Max = 0xffffffff

	// Int64Min is the minimum signed 64-bit integer (-9223372036854775808, 0x8000000000000000)
	Int64Min = -0x8000000000000000

	// Int64Max is the maximum signed 64-bit integer (9223372036854775807, 0x7fffffffffffffff)
	Int64Max = 0x7fffffffffffffff

	// Uint64Max is the maximum unsigned 64-bit integer (18446744073709551615, 0xffffffffffffffff)
	Uint64Max = 0xffffffffffffffff
)

// Bit width constants
const (
	// BitsPerByte is the number of bits in a byte
	BitsPerByte = 8

	// Uint8BitWidth is the bit width of uint8
	Uint8BitWidth = 8

	// Uint16BitWidth is the bit width of uint16
	Uint16BitWidth = 16

	// Uint32BitWidth is the bit width of uint32
	Uint32BitWidth = 32

	// Uint64BitWidth is the bit width of uint64
	Uint64BitWidth = 64
)

// Mask constants for bit manipulation
const (
	// Uint8Mask is the full 8-bit mask (0xff)
	Uint8Mask = Uint8Max

	// Uint16Mask is the full 16-bit mask (0xffff)
	Uint16Mask = Uint16Max

	// Uint24Mask is the full 24-bit mask (0xffffff)
	Uint24Mask = 0xffffff

	// Uint32Mask is the full 32-bit mask (0xffffffff)
	Uint32Mask = Uint32Max

	// Uint64Mask is the full 64-bit mask (0xffffffffffffffff)
	Uint64Mask = Uint64Max
)

// BitBufferRefillThreshold is the threshold for refilling bit buffers
// When a bit buffer has this many or fewer bits remaining, it should be refilled
const BitBufferRefillThreshold = 24
