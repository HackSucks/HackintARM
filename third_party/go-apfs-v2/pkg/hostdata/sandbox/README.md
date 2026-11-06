# sandbox

Capture of the actual App Sandbox process selector. `CaptureAppSandbox` uses the native Darwin observation and returns an explicit unsupported error where that observation is unavailable. Portable captured operations receive their source process context explicitly; a foreign host is never reported as a Darwin sandbox merely because a flag was supplied.

Use [hostdata](../README.md) for complete held/path lifecycle operations. The
[package migration guide](../../../docs/hostdata-packages.md) describes import
changes and the unchanged cross-platform qualification requirements.
