// Signal handling utilities for APFS tools
package tools

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// SignalHandler is a function type for signal callbacks
type SignalHandler func(sig os.Signal)

// signalManager holds the global signal handling state
type signalManager struct {
	signalChan chan os.Signal
	handler    SignalHandler
	attached   bool
}

var globalSignalManager = &signalManager{
	signalChan: make(chan os.Signal, 1),
}

// AttachSignalHandler attaches a signal handler for interrupt signals
// This handles SIGINT (Ctrl+C) and SIGTERM on Unix, and equivalent on Windows
func AttachSignalHandler(handler SignalHandler) error {
	if handler == nil {
		return fmt.Errorf("signal handler cannot be nil")
	}

	if globalSignalManager.attached {
		return fmt.Errorf("signal handler already attached")
	}

	globalSignalManager.handler = handler
	globalSignalManager.attached = true

	// Register for interrupt signals
	signal.Notify(globalSignalManager.signalChan,
		os.Interrupt,    // SIGINT (Ctrl+C)
		syscall.SIGTERM, // SIGTERM
	)

	// Start the signal handling goroutine
	go func() {
		for sig := range globalSignalManager.signalChan {
			if globalSignalManager.handler != nil {
				globalSignalManager.handler(sig)
			}
		}
	}()

	return nil
}

// DetachSignalHandler detaches the current signal handler
func DetachSignalHandler() error {
	if !globalSignalManager.attached {
		return fmt.Errorf("no signal handler attached")
	}

	// Stop receiving signals
	signal.Stop(globalSignalManager.signalChan)

	// Clear the handler
	globalSignalManager.handler = nil
	globalSignalManager.attached = false

	return nil
}

// WaitForSignal blocks until a signal is received and returns it
func WaitForSignal() os.Signal {
	return <-globalSignalManager.signalChan
}

// IsSignalHandlerAttached returns whether a signal handler is currently attached
func IsSignalHandlerAttached() bool {
	return globalSignalManager.attached
}

// SetupDefaultSignalHandler sets up a default signal handler that exits on SIGINT/SIGTERM
// This is a convenience function for simple tools
func SetupDefaultSignalHandler() error {
	return AttachSignalHandler(func(sig os.Signal) {
		fmt.Fprintf(os.Stderr, "\nReceived signal: %v\n", sig)
		fmt.Fprintf(os.Stderr, "Shutting down...\n")
		os.Exit(0)
	})
}

// SetupAbortSignalHandler sets up a signal handler that sets an abort flag
// This is useful for tools that need to clean up before exiting
func SetupAbortSignalHandler(abortFlag *bool) error {
	if abortFlag == nil {
		return fmt.Errorf("abort flag pointer cannot be nil")
	}

	return AttachSignalHandler(func(sig os.Signal) {
		fmt.Fprintf(os.Stderr, "\nReceived signal: %v\n", sig)
		*abortFlag = true
	})
}

// IgnoreSignals configures the program to ignore certain signals
func IgnoreSignals(signals ...os.Signal) {
	signal.Ignore(signals...)
}

// ResetSignals resets signal handlers to their default behavior
func ResetSignals(signals ...os.Signal) {
	signal.Reset(signals...)
}

// NotifyOnSignals creates a channel and registers it to receive the specified signals
// The caller is responsible for reading from the channel
func NotifyOnSignals(signals ...os.Signal) chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, signals...)
	return sigChan
}
