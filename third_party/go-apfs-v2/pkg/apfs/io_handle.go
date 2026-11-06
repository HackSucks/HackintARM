// Input/Output (IO) handle functions
package apfs

import (
	"container/list"
	"fmt"
	"sync"
)

// nodeCacheMaxEntries bounds the parsed B-tree node LRU cache. Traversals
// re-descend from the root for every lookup, so without a cache the same
// omap and fs-tree nodes are re-read and re-parsed from disk thousands of
// times. 512 nodes is ~2 MB of block data at the default 4 KB block size.
const nodeCacheMaxEntries = 512

// nodeCacheEntry is one cached parsed B-tree node
type nodeCacheEntry struct {
	blockNumber uint64
	node        *BTreeNode
}

// Container and volume signatures
var (
	ContainerSignature = [4]byte{'N', 'X', 'S', 'B'}
	VolumeSignature    = [4]byte{'A', 'P', 'S', 'B'}
)

// IOHandle represents the Input/Output handle for APFS operations
type IOHandle struct {
	// The bytes per sector
	BytesPerSector uint16

	// The block size
	BlockSize uint32

	// The container size
	ContainerSize uint64

	// Value to indicate if abort was signalled
	Abort bool

	// The profiler (only available when built with profiler tag)
	Profiler *Profiler

	// LRU cache of parsed B-tree nodes keyed by physical block number.
	// Cached nodes are shared and must be treated as read-only by callers.
	nodeCacheMu sync.Mutex
	nodeCache   map[uint64]*list.Element
	nodeLRU     *list.List // front = most recently used; values are *nodeCacheEntry
}

// getCachedNode returns the cached parsed node for a physical block, if any
func (h *IOHandle) getCachedNode(blockNumber uint64) *BTreeNode {
	h.nodeCacheMu.Lock()
	defer h.nodeCacheMu.Unlock()

	if h.nodeCache == nil {
		return nil
	}

	element, ok := h.nodeCache[blockNumber]
	if !ok {
		return nil
	}

	h.nodeLRU.MoveToFront(element)
	return element.Value.(*nodeCacheEntry).node
}

// putCachedNode stores a parsed node in the LRU cache
func (h *IOHandle) putCachedNode(blockNumber uint64, node *BTreeNode) {
	h.nodeCacheMu.Lock()
	defer h.nodeCacheMu.Unlock()

	if h.nodeCache == nil {
		h.nodeCache = make(map[uint64]*list.Element)
		h.nodeLRU = list.New()
	}

	if element, ok := h.nodeCache[blockNumber]; ok {
		h.nodeLRU.MoveToFront(element)
		element.Value.(*nodeCacheEntry).node = node
		return
	}

	h.nodeCache[blockNumber] = h.nodeLRU.PushFront(&nodeCacheEntry{blockNumber: blockNumber, node: node})

	for h.nodeLRU.Len() > nodeCacheMaxEntries {
		oldest := h.nodeLRU.Back()
		delete(h.nodeCache, oldest.Value.(*nodeCacheEntry).blockNumber)
		h.nodeLRU.Remove(oldest)
	}
}

// NewIOHandle creates a new IO handle with default values
func NewIOHandle() (*IOHandle, error) {
	ioHandle := &IOHandle{
		BytesPerSector: 512,  // Default sector size
		BlockSize:      4096, // Default APFS block size (4KB)
		ContainerSize:  0,
		Abort:          false,
	}

	// Initialize profiler (conditionally compiled)
	profiler, err := NewProfiler()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize profiler: %w", err)
	}

	if err := profiler.Open("profiler.csv"); err != nil {
		return nil, fmt.Errorf("unable to open profiler: %w", err)
	}

	ioHandle.Profiler = profiler

	return ioHandle, nil
}

// Clear resets the IO handle to default values
func (h *IOHandle) Clear() error {
	if h == nil {
		return nil
	}

	h.BytesPerSector = 512
	h.BlockSize = 4096
	h.ContainerSize = 0
	h.Abort = false

	return nil
}

// Close releases resources associated with the IO handle
func (h *IOHandle) Close() error {
	if h == nil {
		return nil
	}

	// Close and free profiler if it exists
	if h.Profiler != nil {
		if err := h.Profiler.Close(); err != nil {
			return fmt.Errorf("unable to close profiler: %w", err)
		}
		h.Profiler = nil
	}

	return nil
}
