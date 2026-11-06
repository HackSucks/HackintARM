// Debug tracing helpers. Output is enabled by the `debug` build tag, which
// sets DebugOutput; see debug.go and debug_stub.go.
package apfs

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	// notifyStream is where debug tracing is written.
	notifyStream io.Writer = os.Stderr

	// notifyMutex protects notifyStream.
	notifyMutex sync.RWMutex
)

// notifyPrintf writes a formatted trace message to the debug stream. It is
// safe for concurrent use and is a no-op unless debug output is enabled.
func notifyPrintf(format string, args ...any) {
	if !DebugOutput {
		return
	}

	notifyMutex.RLock()
	stream := notifyStream
	notifyMutex.RUnlock()

	fmt.Fprintf(stream, format, args...)
}

// isVerbose reports whether debug tracing is enabled.
func isVerbose() bool {
	return DebugOutput
}
