// Derived from zlib's deflate_slow and trees algorithms, Copyright (C)
// 1995-2022 Jean-loup Gailly and Mark Adler. See ZLIB_LICENSE.
// This Go implementation is an altered version, not the original zlib.
package decmpfs

import "math/bits"

type deflateToken struct{ literal, length, distance int }
type deflateCode struct {
	value  uint16
	length int
}
type deflateBits struct {
	bytes []byte
	value uint64
	count int
}

func (b *deflateBits) put(value, count int) {
	b.value |= uint64(value) << b.count
	b.count += count
	for b.count >= 8 {
		b.bytes = append(b.bytes, byte(b.value))
		b.value >>= 8
		b.count -= 8
	}
}
func (b *deflateBits) align() {
	if b.count > 0 {
		b.bytes = append(b.bytes, byte(b.value))
		b.value = 0
		b.count = 0
	}
}
func (b *deflateBits) code(c deflateCode) { b.put(int(c.value), c.length) }

var lengthBase = []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
var lengthExtra = []int{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
var distanceBase = []int{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
var distanceExtra = []int{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
var bitLengthOrder = []int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

func rangeCode(value int, base []int) int {
	i := len(base) - 1
	for base[i] > value {
		i--
	}
	return i
}
func assignDeflateCodes(lengths []int) []deflateCode {
	var counts, next [16]int
	for _, n := range lengths {
		if n != 0 {
			counts[n]++
		}
	}
	code := 0
	for n := 1; n < 16; n++ {
		code = (code + counts[n-1]) << 1
		next[n] = code
	}
	out := make([]deflateCode, len(lengths))
	for i, n := range lengths {
		if n != 0 {
			out[i] = deflateCode{bits.Reverse16(uint16(next[n])) >> uint(16-n), n}
			next[n]++
		}
	}
	return out
}

// Tree ordering includes zlib's depth tie-break and heap traversal. Equal
// frequency trees are valid but are not interchangeable for byte parity.
func deflateTree(frequencies []int, maximum int) []deflateCode {
	count := len(frequencies)
	freq := make([]int, 2*count+1)
	copy(freq, frequencies)
	depth := make([]int, len(freq))
	parent := make([]int, len(freq))
	lengths := make([]int, len(freq))
	heap := []int{0}
	largest := -1
	for i, n := range frequencies {
		if n != 0 {
			heap = append(heap, i)
			largest = i
		}
	}
	for len(heap) < 3 {
		n := 0
		if largest < 2 {
			largest++
			n = largest
		}
		freq[n] = 1
		heap = append(heap, n)
	}
	less := func(a, b int) bool { return freq[a] < freq[b] || freq[a] == freq[b] && depth[a] <= depth[b] }
	down := func(k int) {
		v := heap[k]
		for j := k * 2; j < len(heap); j = k * 2 {
			if j+1 < len(heap) && less(heap[j+1], heap[j]) {
				j++
			}
			if less(v, heap[j]) {
				break
			}
			heap[k] = heap[j]
			k = j
		}
		heap[k] = v
	}
	for k := (len(heap) - 1) / 2; k >= 1; k-- {
		down(k)
	}
	ordered := make([]int, 0, 2*count)
	node := count
	for len(heap) > 2 {
		n := heap[1]
		heap[1] = heap[len(heap)-1]
		heap = heap[:len(heap)-1]
		down(1)
		m := heap[1]
		ordered = append(ordered, n, m)
		freq[node] = freq[n] + freq[m]
		depth[node] = max(depth[n], depth[m]) + 1
		parent[n] = node
		parent[m] = node
		heap[1] = node
		node++
		down(1)
	}
	ordered = append(ordered, heap[1])
	var counts [16]int
	overflow := 0
	for i := len(ordered) - 2; i >= 0; i-- {
		n := ordered[i]
		length := lengths[parent[n]] + 1
		if length > maximum {
			length = maximum
			overflow++
		}
		lengths[n] = length
		if n <= largest {
			counts[length]++
		}
	}
	if overflow > 0 {
		for overflow > 0 {
			n := maximum - 1
			for counts[n] == 0 {
				n--
			}
			counts[n]--
			counts[n+1] += 2
			counts[maximum]--
			overflow -= 2
		}
		cursor := 0
		for length := maximum; length > 0; length-- {
			for n := counts[length]; n > 0; {
				symbol := ordered[cursor]
				cursor++
				if symbol > largest {
					continue
				}
				lengths[symbol] = length
				n--
			}
		}
	}
	return assignDeflateCodes(lengths[:largest+1])
}

type deflateRun struct{ symbol, value, width int }

func deflateRuns(codes []deflateCode) []deflateRun {
	var out []deflateRun
	previous := -1
	next := codes[0].length
	count := 0
	maximum, minimum := 7, 4
	if next == 0 {
		maximum, minimum = 138, 3
	}
	for i := range codes {
		current := next
		next = 65535
		if i+1 < len(codes) {
			next = codes[i+1].length
		}
		count++
		if count < maximum && current == next {
			continue
		}
		switch {
		case count < minimum:
			for n := 0; n < count; n++ {
				out = append(out, deflateRun{symbol: current})
			}
		case current != 0:
			if current != previous {
				out = append(out, deflateRun{symbol: current})
				count--
			}
			out = append(out, deflateRun{16, count - 3, 2})
		case count <= 10:
			out = append(out, deflateRun{17, count - 3, 3})
		default:
			out = append(out, deflateRun{18, count - 11, 7})
		}
		count = 0
		previous = current
		if next == 0 {
			maximum, minimum = 138, 3
		} else if current == next {
			maximum, minimum = 6, 3
		} else {
			maximum, minimum = 7, 4
		}
	}
	return out
}
func deflateBlock(b *deflateBits, tokens []deflateToken, raw []byte, last bool) {
	literalFreq := make([]int, 286)
	distanceFreq := make([]int, 30)
	literalFreq[256] = 1
	for _, t := range tokens {
		if t.length == 0 {
			literalFreq[t.literal]++
		} else {
			literalFreq[257+rangeCode(t.length, lengthBase)]++
			distanceFreq[rangeCode(t.distance, distanceBase)]++
		}
	}
	literals := deflateTree(literalFreq, 15)
	distances := deflateTree(distanceFreq, 15)
	fixedLengths := make([]int, 288)
	for i := range fixedLengths {
		switch {
		case i < 144:
			fixedLengths[i] = 8
		case i < 256:
			fixedLengths[i] = 9
		case i < 280:
			fixedLengths[i] = 7
		default:
			fixedLengths[i] = 8
		}
	}
	fixedLiterals := assignDeflateCodes(fixedLengths)
	fixedLengths = make([]int, 32)
	for i := range fixedLengths {
		fixedLengths[i] = 5
	}
	fixedDistances := assignDeflateCodes(fixedLengths)
	runs := append(deflateRuns(literals), deflateRuns(distances)...)
	runFreq := make([]int, 19)
	for _, r := range runs {
		runFreq[r.symbol]++
	}
	runCodes := deflateTree(runFreq, 7)
	nRun := 19
	for nRun > 4 && (bitLengthOrder[nRun-1] >= len(runCodes) || runCodes[bitLengthOrder[nRun-1]].length == 0) {
		nRun--
	}
	cost := func(l, d []deflateCode) int {
		n := l[256].length
		for _, t := range tokens {
			if t.length == 0 {
				n += l[t.literal].length
			} else {
				lc, dc := rangeCode(t.length, lengthBase), rangeCode(t.distance, distanceBase)
				n += l[257+lc].length + lengthExtra[lc] + d[dc].length + distanceExtra[dc]
			}
		}
		return n
	}
	dynamic := cost(literals, distances) + 14 + 3*nRun
	for _, r := range runs {
		dynamic += runCodes[r.symbol].length + r.width
	}
	fixed := cost(fixedLiterals, fixedDistances)
	dynamicBytes, fixedBytes := (dynamic+10)/8, (fixed+10)/8
	best := min(dynamicBytes, fixedBytes)
	final := 0
	if last {
		final = 1
	}
	if len(raw)+4 <= best && len(raw) <= 65535 {
		b.put(final, 3)
		b.align()
		n := len(raw)
		b.bytes = append(b.bytes, byte(n), byte(n>>8), byte(^n), byte(^n>>8))
		b.bytes = append(b.bytes, raw...)
		return
	}
	if fixedBytes == best {
		b.put(2+final, 3)
		literals, distances = fixedLiterals, fixedDistances
	} else {
		b.put(4+final, 3)
		b.put(len(literals)-257, 5)
		b.put(len(distances)-1, 5)
		b.put(nRun-4, 4)
		for _, symbol := range bitLengthOrder[:nRun] {
			length := 0
			if symbol < len(runCodes) {
				length = runCodes[symbol].length
			}
			b.put(length, 3)
		}
		for _, r := range runs {
			b.code(runCodes[r.symbol])
			b.put(r.value, r.width)
		}
	}
	for _, t := range tokens {
		if t.length == 0 {
			b.code(literals[t.literal])
		} else {
			lc, dc := rangeCode(t.length, lengthBase), rangeCode(t.distance, distanceBase)
			b.code(literals[lc+257])
			b.put(t.length-lengthBase[lc], lengthExtra[lc])
			b.code(distances[dc])
			b.put(t.distance-distanceBase[dc], distanceExtra[dc])
		}
	}
	b.code(literals[256])
}

// encodeZlibBlock reproduces the level-five, 32-KiB-window block encoder used
// by the native filesystem producer. decmpfs omits the Adler-32 trailer.
// Its caller bounds input to a single 64-KiB compression unit.
func encodeZlibBlock(src []byte) []byte {
	head := make([]int, 32768)
	previous := make([]int, len(src))
	insert := func(at int) int {
		h := (int(src[at])<<10 ^ int(src[at+1])<<5 ^ int(src[at+2])) & 32767
		old := head[h]
		previous[at] = old
		head[h] = at
		return old
	}
	output := deflateBits{bytes: []byte{0x78, 0x5e}}
	tokens := make([]deflateToken, 0, 16384)
	start, at := 0, 0
	matchLength, matchStart := 2, 0
	available := false
	flush := func(end int, last bool) {
		deflateBlock(&output, tokens, src[start:end], last)
		tokens = tokens[:0]
		start = end
	}
	for at < len(src) {
		candidate := 0
		if at+2 < len(src) {
			candidate = insert(at)
		}
		oldLength, oldMatch := matchLength, matchStart
		matchLength = 2
		if candidate != 0 && oldLength < 16 && at-candidate <= 32506 {
			best := oldLength
			chain := 32
			if oldLength >= 8 {
				chain /= 4
			}
			nice := min(32, len(src)-at)
			limit := max(0, at-32506)
			for candidate > 0 && chain > 0 {
				length := 0
				for length < min(258, len(src)-at) && src[at+length] == src[candidate+length] {
					length++
				}
				if length > best {
					best = length
					matchStart = candidate
					if length >= nice {
						break
					}
				}
				candidate = previous[candidate]
				chain--
				if candidate <= limit {
					break
				}
			}
			matchLength = min(best, len(src)-at)
			if matchLength == 3 && at-matchStart > 4096 {
				matchLength = 2
			}
		}
		if oldLength >= 3 && matchLength <= oldLength {
			tokens = append(tokens, deflateToken{length: oldLength, distance: at - 1 - oldMatch})
			for n := oldLength - 2; n > 0; n-- {
				at++
				if at+2 < len(src) {
					insert(at)
				}
			}
			available = false
			matchLength = 2
			at++
			if len(tokens) == 16383 {
				flush(at, false)
			}
		} else if available {
			tokens = append(tokens, deflateToken{literal: int(src[at-1])})
			if len(tokens) == 16383 {
				flush(at, false)
			}
			at++
		} else {
			available = true
			at++
		}
	}
	if available {
		tokens = append(tokens, deflateToken{literal: int(src[at-1])})
	}
	flush(at, true)
	output.align()
	return output.bytes
}
